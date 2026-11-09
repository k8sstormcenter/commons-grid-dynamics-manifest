#!/usr/bin/env python3
"""
adr_kpi.py <namespace> [--since EPOCH] [--until EPOCH] [--scan FILE] [--out kpi.json]

The KPI file the harness writes after each iteration. Thin wrapper over engine.evaluate:
every ADR is declared in adrs.yaml and judged by engine.py over evidence.py events.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine import evaluate, main  # noqa: F401  (evaluate is imported by adr_mcp)

if __name__ == "__main__":
    main()
