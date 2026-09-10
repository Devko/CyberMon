from playwright.sync_api import sync_playwright
from pathlib import Path
import json,sys
sys.path.insert(0,str(Path.cwd()))
from tools.site_smoke import PAGES
out=Path('docs/review-2026-09-10')
results=[]
with sync_playwright() as p:
 b=p.chromium.launch(headless=True)
 for name in PAGES:
  page=b.new_page(viewport={'width':1440,'height':900}); errors=[]; failed=[]
  page.on('pageerror',lambda e:errors.append(str(e)))
  page.on('console',lambda m:errors.append(m.text) if m.type=='error' else None)
  page.on('response',lambda r:failed.append([r.status,r.url]) if r.status>=400 else None)
  try:
   r=page.goto('https://devko.github.io/CyberMon/'+name,wait_until='networkidle',timeout=30000)
   item={'page':name,'status':r.status,'errors':errors,'failed_http':failed,'error_cards':page.locator('.error-card').all_text_contents(),'footer':page.locator('#footer-meta').inner_text(),'overflow':page.evaluate('document.documentElement.scrollWidth>innerWidth')}
   if name in ['cve.html','ai.html','epss.html']:
    page.screenshot(path=str(out/(name.replace('.html','')+'-desktop.png')),full_page=True)
   page.set_viewport_size({'width':390,'height':844})
   item['mobile_overflow']=page.evaluate('document.documentElement.scrollWidth>innerWidth')
   if name=='index.html':page.screenshot(path=str(out/'index-mobile.png'),full_page=True)
  except Exception as e:item={'page':name,'exception':str(e)}
  results.append(item);print(json.dumps(item),flush=True);page.close()
 b.close()
(out/'live-pages.json').write_text(json.dumps(results,indent=2),encoding='utf8')
