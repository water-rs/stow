import json,sys,re,collections,os
d=json.load(open(sys.argv[1])); ftbl=d['ftbl']; M=1<<20
depth=int(sys.argv[2])
root='/home/ubuntu/repos/stow/resolve/'
parsed=[]
for f in ftbl:
    m=re.match(r'0x[0-9a-f]+: (.*) \(([^()]*?):(\d+):\d+\)$',f)
    parsed.append((m.group(1),m.group(2),m.group(3)) if m else (f,'',''))
def ours(p):
    n,loc,_=p
    return loc.startswith('src/') and os.path.exists(root+loc) and 'resolve_memprof' not in loc and not n.startswith(('fmt<','clone_one','clone_to_uninit'))
def site(fs):
    hint=''
    for i in fs:
        n,loc,l=parsed[i]
        if ours(parsed[i]): break
        m=re.search(r'(stow_resolve::[\w:]+|cargo_platform::[\w:]+|semver::[\w:]+|serde_json::[\w:]+|toml\w*::[\w:]+|zlib|tar::|gix\w*|git2)',n+loc)
        if m and not hint: hint=m.group(1)
        if not hint and re.match(r'[\w\-]+-\d+\.\d+\.\d+/',loc): hint=loc.split('/')[0]
    out=[]
    for i in fs:
        if ours(parsed[i]):
            n,loc,l=parsed[i]; n=re.sub(r'<.*','',n)
            out.append(f"{n}@{loc[4:]}:{l}")
            if len(out)>=depth: break
    return ' < '.join(out or ['(no stow frame)'])+(f" [{hint}]" if hint else '')
agg=collections.defaultdict(lambda:[0,0,0,0])
for pp in d['pps']:
    a=agg[site(pp['fs'])]; a[0]+=pp['tb']; a[1]+=pp['tbk']; a[2]+=pp.get('gb',0); a[3]+=pp.get('gbk',0)
print(f"total {sum(a[0] for a in agg.values())/M:.1f} MiB; at t-gmax {sum(a[2] for a in agg.values())/M:.1f} MiB; sites {len(agg)}")
for title,idx in (("BY BYTES LIVE AT GLOBAL PEAK",2),("BY TOTAL BYTES ALLOCATED",0)):
    print("\n"+title); print(f"{'#':>2} {'peakMiB':>8} {'peakBlk':>8} {'totMiB':>8} {'totBlk':>9}  site")
    for n,(k,a) in enumerate(sorted(agg.items(), key=lambda kv:-kv[1][idx])[:int(sys.argv[3]) if len(sys.argv)>3 else 15],1):
        print(f"{n:>2} {a[2]/M:>8.1f} {a[3]:>8} {a[0]/M:>8.1f} {a[1]:>9}  {k}")
