from playwright.sync_api import sync_playwright
from pathlib import Path
import json
out=Path('docs/review-2026-09-10')
with sync_playwright() as p:
 b=p.chromium.launch(headless=True);page=b.new_page(viewport={'width':1440,'height':900})
 for name in ['index','epss']:
  page.goto('https://devko.github.io/CyberMon/'+name+'.html',wait_until='networkidle')
  if name=='epss':page.locator('#sections').scroll_into_view_if_needed()
  page.screenshot(path=str(out/(name+'-viewport.png')))
 page.set_viewport_size({'width':390,'height':844});page.goto('https://devko.github.io/CyberMon/cve.html',wait_until='networkidle');page.wait_for_timeout(400)
 print('mobile stable width',page.evaluate('document.documentElement.scrollWidth'))
 b.close()
