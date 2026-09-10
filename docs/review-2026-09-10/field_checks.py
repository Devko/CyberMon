from playwright.sync_api import sync_playwright
from pathlib import Path
import json,re,gzip,struct,collections
out=Path('docs/review-2026-09-10'); results={}
with sync_playwright() as p:
 b=p.chromium.launch(headless=True)
 page=b.new_page(viewport={'width':1440,'height':900})
 page.goto('https://devko.github.io/CyberMon/field.html',wait_until='networkidle')
 page.wait_for_function("document.querySelector('#f-count').textContent !== '—'")
 page.wait_for_timeout(1000)
 meta=page.request.get('https://devko.github.io/CyberMon/field/field.json').json()
 blob=page.request.get('https://devko.github.io/CyberMon/field/'+meta['bin']).body()
 rows=list(struct.iter_unpack('<HIHBBHHHHHHBx',gzip.decompress(blob)))
 results['edition']=meta['generated_at'];results['record_count']=len(rows)
 for layout,col,n in [('cna',6,48),('vendor',8,48),('cwe',7,30)]:
  groups=collections.Counter(r[col] for r in rows if layout!='vendor' or r[col]!=0)
  chosen={k for k,c in groups.most_common(n)}
  results[layout]={'actually_placed':sum(c for k,c in groups.most_common(n)),'matching_filter':sum(groups.values()),'actually_placed_kev':sum(bool(r[11]&1) for r in rows if r[col] in chosen)}
 page.locator('#f-select').click()
 box=page.locator('#f-canvas').bounding_box()
 page.mouse.move(box['x']+3,box['y']+3);page.mouse.down();page.mouse.move(box['x']+box['width']-3,box['y']+box['height']-3,steps=5);page.mouse.up()
 results['selection_before_cut']=page.locator('#f-sel').inner_text()
 page.locator('#f-asof').evaluate("e=>{e.value='0';e.dispatchEvent(new Event('input',{bubbles:true}))}")
 results['selection_after_cut']={'count':page.locator('#f-count').inner_text(),'label':page.locator('#f-count-k').inner_text(),'panel':page.locator('#f-sel').inner_text()}
 page.screenshot(path=str(out/'selection-time-cut.png'))
 page.locator('#f-sel-clear').click()
 results['after_clear']=page.locator('#f-count').inner_text()
 page.locator('#f-size').evaluate("e=>{e.value='2';e.dispatchEvent(new Event('input',{bubbles:true}))}")
 results['size_url']=page.url
 # Exact deployed-source equality to reviewed checkout.
 results['source_matches']={name:page.request.get('https://devko.github.io/CyberMon/'+name).body()==Path('site',name).read_bytes() for name in ['field.html','js/field.js','css/field.css']}
 # The JS module's top-level palette resolves THREE before boot checks it.
 fail=b.new_page();fail.route('**/three.min.js',lambda r:r.abort());err=[];fail.on('pageerror',lambda e:err.append(str(e)))
 fail.goto('https://devko.github.io/CyberMon/field.html',wait_until='networkidle');results['cdn_failure']={'errors':err,'notice_visible':fail.locator('#f-notice').is_visible(),'count':fail.locator('#f-count').inner_text()}
 b.close()
(out/'field-checks.json').write_text(json.dumps(results,indent=2),encoding='utf8');print(json.dumps(results,indent=2))
