from playwright.sync_api import sync_playwright
from pathlib import Path
import json,struct,gzip,collections
out=Path('docs/review-2026-09-10');results={}
with sync_playwright() as p:
 b=p.chromium.launch(headless=True);page=b.new_page(viewport={'width':390,'height':844})
 page.goto('https://devko.github.io/CyberMon/cve.html',wait_until='networkidle')
 results['mobile_width']=page.evaluate('({viewport:innerWidth,document:document.documentElement.scrollWidth})')
 results['overflow_elements']=page.evaluate("[...document.querySelectorAll('body *')].map(e=>({tag:e.tagName,cls:e.className,id:e.id,x:e.getBoundingClientRect().x,right:e.getBoundingClientRect().right,w:e.getBoundingClientRect().width,text:e.textContent.slice(0,60)})).filter(x=>x.right>innerWidth+1&&x.w>0).slice(0,35)")
 page.screenshot(path=str(out/'cve-mobile-top.png'))
 results['source_matches_normalized']={name:page.request.get('https://devko.github.io/CyberMon/'+name).text().replace('\r\n','\n')==Path('site',name).read_text(encoding='utf8') for name in ['field.html','js/field.js','css/field.css']}
 # Compare the sixteen scored buckets with the site's original chart data.
 r=page.request.get('https://devko.github.io/CyberMon/data/score_vs_reality.json');data=r.json()
 meta=page.request.get('https://devko.github.io/CyberMon/field/field.json').json();rows=list(struct.iter_unpack('<HIHBBHHHHHHBx',gzip.decompress(page.request.get('https://devko.github.io/CyberMon/field/'+meta['bin']).body())))
 counts=collections.Counter()
 for row in rows:
  s,e=row[3],row[5]
  if s==255 or e==65535:continue
  sb='9.0-10.0' if s>=90 else '7.0-8.9' if s>=70 else '4.0-6.9' if s>=40 else '0.1-3.9'
  eb='>10%' if e>=1000 else '1-10%' if e>=100 else '0.1-1%' if e>=10 else '<0.1%'
  counts[sb,eb]+=1
 results['grid_differences']=[dict(cell,field_n=counts[cell['cvss_bucket'],cell['epss_bucket']]) for cell in data['grid'] if cell['n']!=counts[cell['cvss_bucket'],cell['epss_bucket']]]
 results['meta_bytes']={k:meta[k] for k in ['n','raw_bytes','bin_bytes']}
 b.close()
(out/'extra-checks.json').write_text(json.dumps(results,indent=2),encoding='utf8');print(json.dumps(results,indent=2))
