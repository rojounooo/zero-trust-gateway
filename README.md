# Zero Trust Gateway for Hospital Networks

## Overview
This project implements a proof-of-concept Zero Trust gateway designed for a simulated hospital environment. The system enforces strict authentication, authorisation, and policy-based access control using a gateway architecture.

The solution integrates:
- **Keycloak** (Identity Provider)
- **Envoy Proxy** (Policy Enforcement Point)
- **Open Policy Agent (OPA)** (Policy Decision Point)

## Architecture
All incoming requests pass through the Envoy gateway, where authentication tokens are validated and forwarded to OPA for policy evaluation. Access is granted or denied based on defined RBAC and TBAC policies.

## Features
- Role-Based Access Control (RBAC)
- Time-Based Access Control (TBAC)
- Rule-based attack detection
- Traffic simulation (normal + attacks)
- KPI-based evaluation
- Low-resource deployment (Raspberry Pi)

## Repository Structure
- `gateway/` → Envoy configurations (ARM + AMD64)
- `policies/` → OPA policy definitions
- `webapp/` → FastAPI application
- `detector/` → Detection engine
- `ingestion/` → FastAPI ingestion server
- `simulation/` → Traffic generation scripts
- `analysis/` → KPI calculation scripts

## Setup
See `setup.md` for full deployment instructions.

## Disclaimer
Sensitive configuration files and credentials have been removed and replaced with example configurations where necessary.
