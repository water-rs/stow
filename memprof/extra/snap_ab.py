import json,sys,collections
s=json.load(open(sys.argv[1])); m=s['snapshot']['meta']
nf=m['node_fields']; ef=m['edge_fields']; nt=m['node_types'][0]; et=m['edge_types'][0]
N=len(nf); E=len(ef); nodes=s['nodes']; edges=s['edges']; strs=s['strings']
iT,iN,iS,iE=nf.index('type'),nf.index('name'),nf.index('self_size'),nf.index('edge_count')
eT,eN,eTo=ef.index('type'),ef.index('name_or_index'),ef.index('to_node')
cnt=len(nodes)//N
first=[0]*(cnt+1)
for i in range(cnt): first[i+1]=first[i]+nodes[i*N+iE]
ret=collections.defaultdict(list)
for i in range(cnt):
    for e in range(first[i],first[i+1]):
        ret[edges[e*E+eTo]//N].append((i,e))
def name(i): return f"{nt[nodes[i*N+iT]]}:{strs[nodes[i*N+iN]][:60]}"
tot=collections.Counter(); big=[]
for i in range(cnt):
    sz=nodes[i*N+iS]; nm=strs[nodes[i*N+iN]]
    tot[(nt[nodes[i*N+iT]],nm[:50])]+=sz
    if sz>256*1024: big.append((sz,i))
print("self_size total MiB %.1f"%(sum(tot.values())/2**20))
for k,v in tot.most_common(15): print(f"{v/2**20:8.2f} {k}")
big.sort(reverse=True)
for sz,i in big[:15]:
    chain=[name(i)]; cur=i
    for _ in range(8):
        r=[x for x in ret[cur] if et[edges[x[1]*E+eT]] not in ('weak',)]
        if not r: break
        p,e=r[0]; en=edges[e*E+eN]; en=strs[en] if et[edges[e*E+eT]] not in ('element','hidden') else en
        chain.append(f"<-{en}- {name(p)}"); cur=p
    print(f"{sz/2**20:7.2f} MiB "+" ".join(chain))
