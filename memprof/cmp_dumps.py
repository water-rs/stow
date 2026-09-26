import json,sys,os,itertools,hashlib
# usage: cmp_dumps.py dirA dirB   -> per target: bytes-equal? ; if not, equal modulo reordering within runs of identical-key adjacent units?
A,B=sys.argv[1],sys.argv[2]
def key(u): return json.dumps(u['key'] if 'key' in u else {k:u[k] for k in ('pkg','platform','side','kind')},sort_keys=True)
def runs(units):
    out=[]
    for k,g in itertools.groupby(units,key=key):
        out.append((k,sorted(json.dumps(u,sort_keys=True) for u in g)))
    return out
for t in sorted(os.listdir(A)):
    a=open(f'{A}/{t}','rb').read(); b=open(f'{B}/{t}','rb').read()
    if a==b: print(f'{t:34} BYTES-EQUAL {hashlib.sha256(a).hexdigest()[:12]}'); continue
    ja,jb=json.loads(a),json.loads(b)
    roots=ja[1]==jb[1]
    ra,rb=runs(ja[0]),runs(jb[0])
    same_runs=ra==rb
    ndiff=sum(1 for x,y in zip(ja[0],jb[0]) if x!=y)
    print(f'{t:34} DIFFER roots_equal={roots} n={len(ja[0])}/{len(jb[0])} differing_positions={ndiff} equal_modulo_same_key_run_order={same_runs}')
