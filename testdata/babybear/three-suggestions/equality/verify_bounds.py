#!/usr/bin/env python3
"""Independent integer proof checks for persistent quintic equality states."""
import random,json
RADIX=1<<64
MASK=RADIX-1

def forms(a):
 return sum(a[i]<<(64*i) for i in range(4)),sum(a[4-i]<<(64*i) for i in range(4))
def coefficients(low,rev):
 return [(low>>(64*i))&0xffffffff for i in range(4)]+[rev&0xffffffff]
def reduced(c,p,baby):
 # Oracle: descending division by the monic defining polynomial.
 c=c[:]
 for k in range(8,4,-1):
  t=c[k]
  if baby:c[k-5]+=2*t
  else:c[k-5]+=t;c[k-3]-=t
  c[k]=0
 return [x%p for x in c[:5]]
def oracle(a,b,p,baby):
 c=[0]*9
 for i in range(5):
  for j in range(5):c[i+j]+=a[i]*b[j]
 return reduced(c,p,baby)
def product(aa,bb,p,baby,eq=False):
 al,ar=aa;bl,br=bb
 low=(al*bl)%2**256;high=(ar*br)%2**256
 c4=(((al*((bl>>64)|((br&0xffffffff)<<192)))%2**256)>>192)+(ar&0xffffffff)*(bl&0xffffffff)
 c=[(low>>(64*i))&MASK for i in range(4)]+[c4]+[(high>>(64*(3-i)))&MASK for i in range(4)]
 if baby:r=[c[0]+2*c[5],c[1]+2*c[6],c[2]+2*c[7],c[3]+2*c[8],c4]
 else:
  bias=p<<40
  assert bias>max(c)
  r=[c[0]+c[5]+bias-c[8],c[1]+c[6],c[2]+bias-c[5]+c[7]+c[8],c[3]+bias-c[6]+c[8],c4+bias-c[7]]
 if eq:r=[2*x+((p+1)//2 if i==0 else 0) for i,x in enumerate(r)]
 assert max(r)<2**73
 return forms([x%p for x in r])
def eq(a,b,p,baby):
 a=a[:];b=b[:];a[0]=(a[0]+p//2)%p;b[0]=(b[0]+p//2)%p
 return coefficients(*product(forms(a),forms(b),p,baby,True))
def eqoracle(a,b,p,baby):
 ab=oracle(a,b,p,baby)
 return [(2*ab[i]-a[i]-b[i]+(i==0))%p for i in range(5)]
reports=[]
for p,baby in [(0x7f000001,False),(0x78000001,True)]:
 assert 4*(p-1)**2<RADIX
 assert 5*(p-1)**2>=RADIX
 assert (p<<40)>5*(p-1)**2
 rng=random.Random(20260906+int(baby));cases=0
 inputs=[([p-1]*5,[p-1]*5),([0]*5,[p-1]*5)]
 for i in range(5):
  for j in range(5):
   a=[0]*5;b=[0]*5;a[i]=p-1;b[j]=p-1;inputs.append((a,b))
 inputs += [([rng.randrange(p) for _ in range(5)],[rng.randrange(p) for _ in range(5)]) for _ in range(10000)]
 for a,b in inputs:
  assert coefficients(*product(forms(a),forms(b),p,baby))==oracle(a,b,p,baby)
  assert coefficients(*product(forms(a),forms(a),p,baby))==oracle(a,a,p,baby)
  assert eq(a,b,p,baby)==eqoracle(a,b,p,baby)
  cases+=1
 for _ in range(100):
  q=[[rng.randrange(p) for _ in range(5)] for _ in range(22)]
  current=[[rng.randrange(p) for _ in range(5)] for _ in range(4)]
  expected=[[1,0,0,0,0] for _ in range(4)];actual=[forms(v) for v in expected]
  point_forms=[forms(v) for v in current]
  for i in range(22):
   for j in range(4):
    if i<22-4*j:
     term=eq(coefficients(*point_forms[j]),q[21-i],p,baby)
     actual[j]=product(actual[j],forms(term),p,baby)
     point_forms[j]=product(point_forms[j],point_forms[j],p,baby)
     expected[j]=oracle(expected[j],eqoracle(current[j],q[21-i],p,baby),p,baby)
     current[j]=oracle(current[j],current[j],p,baby)
  assert [coefficients(*a) for a in actual]==expected
 reports.append({'field':'BabyBear' if baby else 'KoalaBear','kernel_cases':cases,'ood_chain_cases':100,'four_product_lane_max':4*(p-1)**2,'middle_coefficient_max':5*(p-1)**2,'largest_memory_offset':544,'allocated_state_bytes':576})
print(json.dumps({'status':'PASS','reports':reports},indent=2))
