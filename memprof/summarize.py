import json,sys,re
M=1<<20
lines=[]
for l in open(sys.argv[1]):
    m=re.search(r'MEMPROF (\{.*\})',l)
    if m: lines.append(json.loads(m.group(1)))
print(f"{'mark':<20}{'mem_size':>10}{'live':>10}{'win_peak':>10}{'peak':>10}{'total':>10}{'count':>11}{'blocks':>10}{'chunk':>10}{'hdr':>8}")
prev_total=0;prev_count=0
for s in lines:
    print(f"{s['label']:<20}{s['memory_size']/M:>10.1f}{s['live']/M:>10.1f}{s['window_peak']/M:>10.1f}{s['peak']/M:>10.1f}{(s['total']-prev_total)/M:>10.1f}{s['count']-prev_count:>11}{s['live_blocks']:>10}{s['chunk_live']/M:>10.1f}{s['header_live']/M:>8.1f}")
    prev_total=s['total'];prev_count=s['count']
f=lines[-1]
print(f"\nglobal peak live {f['peak']/M:.1f} MiB; memory_size at peak {f['mem_at_peak']/M:.1f}; final memory_size {f['memory_size']/M:.1f}; blocks at peak {f['blocks_at_peak']}; chunk_peak {f['chunk_peak']/M:.1f}; total {f['total']/M:.1f} MiB in {f['count']} allocs")
print(f"\n{'tag':<15}{'at_peak':>10}{'tag_peak':>10}{'live_end':>10}{'total':>10}{'count':>11}")
for k,v in sorted(f['tags'].items(), key=lambda kv:-kv[1]['at_peak']):
    print(f"{k:<15}{v['at_peak']/M:>10.1f}{v['peak']/M:>10.1f}{v['live']/M:>10.1f}{v['total']/M:>10.1f}{v['count']:>11}")
