#!/usr/bin/env python3
"""Render the benchmark summary as a table."""
import json, sys

rows = [json.loads(l) for l in open('/home/user/bench/results/summary.jsonl') if l.strip()]
hdr = f"{'project':<12}{'artifacts':>10}{'cargo':>9}{'stow':>9}{'stow -nr':>10}{'floor':>8}   {'stow gain':>10}{'nr gain':>9}"
print(hdr); print('-'*len(hdr))
# A build that fails exits early and looks fast. Never let that read as a win.
failed = [r for r in rows if any(r[k] for k in ('plain_rc','floor_rc','stow_rc','stow_nr_rc'))]
rows = [r for r in rows if r not in failed]
for r in rows:
    g = r['plain_s']/r['stow_s'] if r['stow_s'] else 0
    gn = r['plain_s']/r['stow_nr_s'] if r['stow_nr_s'] else 0
    print(f"{r['project']:<12}{r['cached_artifacts']:>10}{r['plain_s']:>9.1f}{r['stow_s']:>9.1f}"
          f"{r['stow_nr_s']:>10.1f}{r['floor_s']:>8.1f}   {g:>9.2f}x{gn:>8.2f}x")
for r in failed:
    which = ', '.join(k[:-3] for k in ('plain_rc','floor_rc','stow_rc','stow_nr_rc') if r[k])
    print(f"{r['project']:<12}{r['cached_artifacts']:>10}{'':>36}   BUILD FAILED ({which})")
if rows:
    import statistics
    print('-'*len(hdr))
    print(f"{'median':<12}{'':>10}{statistics.median(r['plain_s'] for r in rows):>9.1f}"
          f"{statistics.median(r['stow_s'] for r in rows):>9.1f}"
          f"{statistics.median(r['stow_nr_s'] for r in rows):>10.1f}"
          f"{statistics.median(r['floor_s'] for r in rows):>8.1f}"
          f"   {statistics.median(r['plain_s']/r['stow_s'] for r in rows):>9.2f}x"
          f"{statistics.median(r['plain_s']/r['stow_nr_s'] for r in rows):>8.2f}x")
