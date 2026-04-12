import argparse
import json
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd


ATTACK_TYPES = ["brute_force", "off_shift", "role_confusion"]


def load_jsonl(path: Path) -> pd.DataFrame:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return pd.DataFrame(rows)


def load_blocklist(path: Path) -> pd.DataFrame:
    rows = []
    if not path.exists():
        return pd.DataFrame(columns=["ip"])
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip:
                rows.append({"ip": ip})
    return pd.DataFrame(rows)


def ensure_columns(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    for col in columns:
        if col not in df.columns:
            df[col] = pd.NA
    return df


def build_attack_sessions(events: pd.DataFrame, gap_seconds: float = 10.0) -> pd.DataFrame:
    attacks = events[events["event_type"] == "attack"].copy()
    if attacks.empty:
        return pd.DataFrame()

    attacks = attacks.sort_values(["phase", "attack_type", "ip", "timestamp"]).copy()
    attacks["prev_ts"] = attacks.groupby(["phase", "attack_type", "ip"])["timestamp"].shift(1)
    attacks["new_session"] = (
        attacks["prev_ts"].isna()
        | ((attacks["timestamp"] - attacks["prev_ts"]) > gap_seconds)
    )

    attacks["session_seq"] = attacks.groupby(["phase", "attack_type", "ip"])["new_session"].cumsum()
    attacks["session_id"] = (
        attacks["phase"].astype(str)
        + "|"
        + attacks["attack_type"].astype(str)
        + "|"
        + attacks["ip"].astype(str)
        + "|"
        + attacks["session_seq"].astype(str)
    )

    grouped = attacks.groupby(["session_id", "phase", "attack_type", "ip"], as_index=False).agg(
        start_ts=("timestamp", "min"),
        end_ts=("timestamp", "max"),
        request_count=("timestamp", "size"),
        success_count=("status", lambda s: int((s == 200).sum())),
        deny_403_count=("status", lambda s: int((s == 403).sum())),
        deny_429_count=("status", lambda s: int((s == 429).sum())),
    )
    return grouped


def match_alerts_to_sessions(sessions: pd.DataFrame, alerts: pd.DataFrame, window_seconds: float = 120.0) -> pd.DataFrame:
    if sessions.empty:
        sessions["detected"] = False
        sessions["first_alert_ts"] = pd.NA
        sessions["mttd_seconds"] = pd.NA
        sessions["matched_alert_count"] = 0
        return sessions

    if alerts.empty:
        sessions = sessions.copy()
        sessions["detected"] = False
        sessions["first_alert_ts"] = pd.NA
        sessions["mttd_seconds"] = pd.NA
        sessions["matched_alert_count"] = 0
        return sessions

    alerts = alerts.sort_values("timestamp").copy()
    matched_first = []
    matched_count = []

    for _, session in sessions.iterrows():
        hits = alerts[
            (alerts["type"] == session["attack_type"])
            & (alerts["ip"] == session["ip"])
            & (alerts["timestamp"] >= session["start_ts"])
            & (alerts["timestamp"] <= session["end_ts"] + window_seconds)
        ].copy()

        matched_count.append(len(hits))
        if hits.empty:
            matched_first.append(pd.NA)
        else:
            matched_first.append(hits["timestamp"].min())

    sessions = sessions.copy()
    sessions["first_alert_ts"] = matched_first
    sessions["matched_alert_count"] = matched_count
    sessions["detected"] = sessions["first_alert_ts"].notna()
    sessions["mttd_seconds"] = sessions["first_alert_ts"] - sessions["start_ts"]
    return sessions


def phase_windows(events: pd.DataFrame) -> pd.DataFrame:
    windows = events.groupby("phase", as_index=False).agg(
        phase_start=("timestamp", "min"),
        phase_end=("timestamp", "max"),
    )
    return windows


def alerts_in_phase(alerts: pd.DataFrame, windows: pd.DataFrame, phase: str) -> pd.DataFrame:
    row = windows[windows["phase"] == phase]
    if row.empty or alerts.empty:
        return alerts.iloc[0:0].copy()

    start_ts = row["phase_start"].iloc[0]
    end_ts = row["phase_end"].iloc[0]
    return alerts[(alerts["timestamp"] >= start_ts) & (alerts["timestamp"] <= end_ts)].copy()


def compute_kpis(events: pd.DataFrame, alerts: pd.DataFrame, blocklist: pd.DataFrame, monitor: pd.DataFrame) -> dict[str, pd.DataFrame]:
    events = ensure_columns(events.copy(), ["phase", "event_type", "attack_type", "ip", "status", "timestamp"])
    alerts = ensure_columns(alerts.copy(), ["timestamp", "ip", "type", "severity", "message"])
    monitor = ensure_columns(monitor.copy(), ["phase", "timestamp", "id", "free"])

    events["timestamp"] = pd.to_numeric(events["timestamp"], errors="coerce")
    alerts["timestamp"] = pd.to_numeric(alerts["timestamp"], errors="coerce")
    monitor["timestamp"] = pd.to_numeric(monitor["timestamp"], errors="coerce")
    events["status"] = pd.to_numeric(events["status"], errors="coerce")

    events = events.dropna(subset=["timestamp"])
    alerts = alerts.dropna(subset=["timestamp"])

    windows = phase_windows(events)
    sessions = build_attack_sessions(events)
    sessions = match_alerts_to_sessions(sessions, alerts)

    detection_rows = []
    overall_total = len(sessions)
    overall_detected = int(sessions["detected"].sum()) if not sessions.empty else 0
    detection_rows.append({
        "scope": "overall",
        "total_attack_sessions": overall_total,
        "detected_sessions": overall_detected,
        "detection_rate_pct": round((overall_detected / overall_total * 100), 2) if overall_total else 0.0,
    })

    for attack_type in ATTACK_TYPES:
        subset = sessions[sessions["attack_type"] == attack_type]
        total = len(subset)
        detected = int(subset["detected"].sum()) if not subset.empty else 0
        detection_rows.append({
            "scope": attack_type,
            "total_attack_sessions": total,
            "detected_sessions": detected,
            "detection_rate_pct": round((detected / total * 100), 2) if total else 0.0,
        })
    detection_df = pd.DataFrame(detection_rows)

    phase1_events = events[events["phase"] == "phase1"]
    phase1_alerts = alerts_in_phase(alerts, windows, "phase1")
    false_positive_df = pd.DataFrame([{
        "phase": "phase1",
        "normal_requests": int(len(phase1_events)),
        "alerts_in_phase": int(len(phase1_alerts)),
        "false_positive_rate_pct": round((len(phase1_alerts) / len(phase1_events) * 100), 4) if len(phase1_events) else 0.0,
    }])

    mttd_rows = []
    for attack_type in ATTACK_TYPES:
        subset = sessions[(sessions["attack_type"] == attack_type) & (sessions["detected"] == True)]
        avg_mttd = float(subset["mttd_seconds"].mean()) if not subset.empty else None
        mttd_rows.append({
            "attack_type": attack_type,
            "detected_sessions": int(len(subset)),
            "mean_time_to_detect_seconds": round(avg_mttd, 3) if avg_mttd is not None else None,
        })
    mttd_df = pd.DataFrame(mttd_rows)

    if blocklist.empty:
        blocklist_df = pd.DataFrame([{
            "blocked_ips": 0,
            "correct_attacker_blocks": 0,
            "false_positive_blocks": 0,
            "blocklist_accuracy_pct": 0.0,
        }])
    else:
        blocked = blocklist["ip"].astype(str)
        correct = blocked.str.startswith("192.168.2.").sum()
        total = len(blocked)
        false_positive_blocks = total - int(correct)
        blocklist_df = pd.DataFrame([{
            "blocked_ips": total,
            "correct_attacker_blocks": int(correct),
            "false_positive_blocks": int(false_positive_blocks),
            "blocklist_accuracy_pct": round((correct / total * 100), 2) if total else 0.0,
        }])

    attack_events = events[events["event_type"] == "attack"]
    successful_attack_requests = int((attack_events["status"] == 200).sum())
    attack_success_df = pd.DataFrame([{
        "total_attack_requests": int(len(attack_events)),
        "successful_attack_requests": successful_attack_requests,
        "attack_success_rate_pct": round((successful_attack_requests / len(attack_events) * 100), 4) if len(attack_events) else 0.0,
    }])

    volume_df = (
        events.groupby(["phase", "event_type"], as_index=False)
        .size()
        .rename(columns={"size": "request_count"})
        .sort_values(["phase", "event_type"])
    )

    control_rows = []
    for attack_type in ATTACK_TYPES:
        subset = attack_events[attack_events["attack_type"] == attack_type]
        total = len(subset)

        if attack_type == "brute_force":
            effective = int((subset["status"] == 429).sum())
            status_name = "429_count"
        else:
            effective = int((subset["status"] == 403).sum())
            status_name = "403_count"

        control_rows.append({
            "attack_type": attack_type,
            "total_attack_requests": total,
            status_name: effective,
            "control_effectiveness_pct": round((effective / total * 100), 2) if total else 0.0,
        })
    control_df = pd.DataFrame(control_rows)

    phase_compare_rows = []
    for phase in ["phase2", "phase3"]:
        subset = sessions[sessions["phase"] == phase]
        total = len(subset)
        detected = int(subset["detected"].sum()) if not subset.empty else 0

        normal_phase_events = events[(events["phase"] == phase) & (events["event_type"] == "normal")]
        phase_alerts = alerts_in_phase(alerts, windows, phase)

        attack_phase_sessions = subset.copy()
        unmatched_alerts = 0
        if not phase_alerts.empty:
            for _, alert in phase_alerts.iterrows():
                match = attack_phase_sessions[
                    (attack_phase_sessions["attack_type"] == alert["type"])
                    & (attack_phase_sessions["ip"] == alert["ip"])
                    & (attack_phase_sessions["start_ts"] <= alert["timestamp"])
                    & (attack_phase_sessions["end_ts"] + 120 >= alert["timestamp"])
                ]
                if match.empty:
                    unmatched_alerts += 1

        phase_compare_rows.append({
            "phase": phase,
            "attack_sessions": total,
            "detected_sessions": detected,
            "detection_rate_pct": round((detected / total * 100), 2) if total else 0.0,
            "normal_requests": int(len(normal_phase_events)),
            "unmatched_alerts": unmatched_alerts,
            "false_positive_under_load_pct": round((unmatched_alerts / len(normal_phase_events) * 100), 4) if len(normal_phase_events) else 0.0,
        })
    phase_compare_df = pd.DataFrame(phase_compare_rows)

    monitor_valid = monitor[monitor["phase"].isin(["phase1", "phase2", "phase3"])].copy()
    if not monitor_valid.empty:
        monitor_valid["cpu_util_pct"] = 100 - pd.to_numeric(monitor_valid["id"], errors="coerce")
        resource_df = monitor_valid.groupby("phase", as_index=False).agg(
            avg_cpu_util_pct=("cpu_util_pct", "mean"),
            peak_cpu_util_pct=("cpu_util_pct", "max"),
            avg_free_kb=("free", "mean"),
            min_free_kb=("free", "min"),
        )
        resource_df["avg_cpu_util_pct"] = resource_df["avg_cpu_util_pct"].round(2)
        resource_df["peak_cpu_util_pct"] = resource_df["peak_cpu_util_pct"].round(2)
        resource_df["avg_free_kb"] = resource_df["avg_free_kb"].round(0)
    else:
        resource_df = pd.DataFrame(columns=["phase", "avg_cpu_util_pct", "peak_cpu_util_pct", "avg_free_kb", "min_free_kb"])

    return {
        "detection_rate": detection_df,
        "false_positive_rate": false_positive_df,
        "mttd": mttd_df,
        "blocklist_accuracy": blocklist_df,
        "attack_success_rate": attack_success_df,
        "request_volume_by_phase": volume_df,
        "control_effectiveness": control_df,
        "phase3_comparison": phase_compare_df,
        "resource_summary": resource_df,
        "attack_sessions": sessions,
    }


def save_tables(results: dict[str, pd.DataFrame], out_dir: Path) -> None:
    for name, df in results.items():
        if name == "attack_sessions":
            continue
        df.to_csv(out_dir / f"{name}.csv", index=False)

    with pd.ExcelWriter(out_dir / "kpi_summary.xlsx", engine="openpyxl") as writer:
        for name, df in results.items():
            if name == "attack_sessions":
                continue
            df.to_excel(writer, index=False, sheet_name=name[:31])


def make_charts(results: dict[str, pd.DataFrame], out_dir: Path) -> None:
    detection = results["detection_rate"]
    det_plot = detection[detection["scope"] != "overall"]
    if not det_plot.empty:
        plt.figure(figsize=(8, 4.5))
        plt.bar(det_plot["scope"], det_plot["detection_rate_pct"])
        plt.ylabel("Detection Rate (%)")
        plt.title("Detection Rate by Attack Type")
        plt.tight_layout()
        plt.savefig(out_dir / "detection_rate_by_attack.png", dpi=200)
        plt.close()

    control = results["control_effectiveness"]
    if not control.empty:
        plt.figure(figsize=(8, 4.5))
        plt.bar(control["attack_type"], control["control_effectiveness_pct"])
        plt.ylabel("Control Effectiveness (%)")
        plt.title("Control Effectiveness by Attack Type")
        plt.tight_layout()
        plt.savefig(out_dir / "control_effectiveness_by_attack.png", dpi=200)
        plt.close()

    volume = results["request_volume_by_phase"]
    if not volume.empty:
        pivot = volume.pivot(index="phase", columns="event_type", values="request_count").fillna(0)
        pivot.plot(kind="bar", figsize=(8, 4.5))
        plt.ylabel("Requests")
        plt.title("Request Volume by Phase")
        plt.tight_layout()
        plt.savefig(out_dir / "request_volume_by_phase.png", dpi=200)
        plt.close()

    resource = results["resource_summary"]
    if not resource.empty:
        plt.figure(figsize=(8, 4.5))
        plt.bar(resource["phase"], resource["avg_cpu_util_pct"])
        plt.ylabel("Average CPU Utilisation (%)")
        plt.title("Average CPU Utilisation by Phase")
        plt.tight_layout()
        plt.savefig(out_dir / "avg_cpu_by_phase.png", dpi=200)
        plt.close()


def print_summary(results: dict[str, pd.DataFrame]) -> None:
    for name, df in results.items():
        if name == "attack_sessions":
            continue
        print("\n" + "=" * 80)
        print(name.upper().replace("_", " "))
        print("=" * 80)
        if df.empty:
            print("(no data)")
        else:
            print(df.to_string(index=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Calculate KPIs from experiment logs.")
    parser.add_argument("--events", default="events.log.txt", help="Path to events log JSONL")
    parser.add_argument("--alerts", default="alerts.log.txt", help="Path to alerts log JSONL")
    parser.add_argument("--blocklist", default="blocklist.txt", help="Path to blocklist file")
    parser.add_argument("--monitor", default="monitor.log.txt", help="Path to monitor log JSONL")
    parser.add_argument("--out", default="kpi_output", help="Output directory for tables and charts")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    events = load_jsonl(Path(args.events))
    alerts = load_jsonl(Path(args.alerts))
    blocklist = load_blocklist(Path(args.blocklist))
    monitor = load_jsonl(Path(args.monitor)) if Path(args.monitor).exists() else pd.DataFrame()

    results = compute_kpis(events, alerts, blocklist, monitor)
    save_tables(results, out_dir)
    make_charts(results, out_dir)
    print_summary(results)

    print("\nSaved outputs to:", out_dir.resolve())


if __name__ == "__main__":
    main()