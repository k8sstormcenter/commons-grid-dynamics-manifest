#!/usr/bin/env python3
"""kpi_to_ch.py <kpi-<ns>-iterN.json> <iteration> [tool]  -> inserts into forensic_db.adr_findings
Same rows the MCP writes (adr_mcp.findings_rows); accepts v1 and v2 kpi files. Needs ADR_CH."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adr_mcp
print(adr_mcp.persist(json.load(open(sys.argv[1])), sys.argv[3] if len(sys.argv) > 3 else "harness", int(sys.argv[2])))
