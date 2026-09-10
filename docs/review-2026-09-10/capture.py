from playwright.sync_api import sync_playwright
from pathlib import Path
import json, time
out=Path('docs/review-2026-09-10')
with sync_playwright() as p:
 b=p.chromium.launch(headless=True)
 page=b.new_page(viewport={'width':1440,'height':900},device_scale_factor=1)
 errors=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 for name in ['index','field']:
  r=page.goto('https://devko.github.io/CyberMon/'+name+'.html',wait_until='networkidle',timeout=60000)
  if name=='field':
   try: page.wait_for_function("document.querySelector('#f-count').textContent !== '—'",timeout=30000)
   except: pass
  page.screenshot(path=str(out/(name+'-desktop.png')),full_page=True)
  print(json.dumps({'page':name,'status':r.status,'text':page.locator('body').inner_text(),'errors':errors}),flush=True)
  if name=='field':
   (out/'field-dom.txt').write_text(page.locator('body').inner_text(),encoding='utf8')
   for layout in ['clock','grid','cna','vendor','cwe','status']:
    page.locator('[data-layout='+layout+']').click()
    page.wait_for_timeout(1300)
    page.screenshot(path=str(out/(layout+'-desktop.png')))
    print(json.dumps({'layout':layout,'count':page.locator('#f-count').inner_text(),'labels':page.locator('#f-labels').inner_text()}),flush=True)
   page.set_viewport_size({'width':390,'height':844})
   page.locator('[data-layout=time]').click()
   page.wait_for_timeout(1200)
   page.evaluate('scrollTo(0,0)')
   page.screenshot(path=str(out/'field-mobile.png'),full_page=True)
   print('mobile '+str(page.evaluate('({w:innerWidth,scroll:document.documentElement.scrollWidth})')),flush=True)
 b.close()
