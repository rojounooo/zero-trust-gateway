import subprocess
import time

LOG_FILE = "/home/<USERNAME>/logs/monitor.log"

def run():
    with open(LOG_FILE, "w") as f:
        f.write("timestamp,r,b,swpd,free,buff,cache,si,so,bi,bo,in,cs,us,sy,id,wa,st\n")

        proc = subprocess.Popen(
            ["vmstat", "5"],
            stdout=subprocess.PIPE,
            text=True
        )

        for line in proc.stdout:
            if line.startswith("procs") or line.startswith(" r"):
                continue

            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{ts},{line.strip()}\n")
            f.flush()


if __name__ == "__main__":
    run()