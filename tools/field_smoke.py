"""Browser regression checks for the Field. Default: isolated synthetic fixture.

--site site validates the assembled deployment with its real Field artifact.
The fixture is never written into the deployed site.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline import field_export as fe
from pipeline.fetch_kev import KevEntry
from tools.fetch_field import validate
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args): pass

@contextmanager
def server(directory):
    http = ThreadingHTTPServer(('127.0.0.1', 0), partial(QuietHandler, directory=str(directory)))
    thread = threading.Thread(target=http.serve_forever, daemon=True); thread.start()
    try: yield f'http://127.0.0.1:{http.server_port}'
    finally: http.shutdown(); http.server_close(); thread.join()


def fixture(directory):
    shutil.copytree(ROOT / 'site', directory, ignore=shutil.ignore_patterns('field', 'data', 'motion', 'carousels'))
    rows = [fe.FieldRow(2026, i + 1, 10000, 40, 3, f'CNA {i:03d}', 79 + i, f'vendor {i:03d}') for i in range(70)]
    rows += [fe.FieldRow(2026, 1001, 10000, 40, 3, 'Median', 79, 'acme'), fe.FieldRow(2026, 1002, 10001, 80, 3, 'Median', 79, 'acme')]
    collector = fe.FieldCollector(rows=rows)
    kev = [KevEntry(cve_id='CVE-2026-1002', date_added='2026-06-01', due_date=None, ransomware_use='Known')]
    packed, meta = fe.build(collector, '2026-09-10T00:00:00Z', epss_scores={'CVE-2026-1001': 0.00996, 'CVE-2026-1002': 0.01}, kev_entries=kev, poc_ids=[], nvd_statuses={}, sources={'cvelist': {'release': 'browser-test-fixture'}}, recent_rescored={'CVE-2026-1001'})
    meta['sample'] = True
    fe.write(directory / 'field', packed, meta)


def check(site, synthetic, screenshots=None, allow_sample=False):
    meta = validate(site / 'field', allow_sample=synthetic or allow_sample)
    with server(site) as base, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={'width':1440,'height':900})
        errors=[]; page.on('pageerror', lambda e: errors.append(str(e)))
        page.add_init_script('window.fieldFrames=0; const originalRAF=requestAnimationFrame; window.requestAnimationFrame=(fn)=>originalRAF.call(window,(t)=>{window.fieldFrames++;fn(t)});')
        def load(suffix=''):
            page.goto(base + '/field.html' + suffix, wait_until='networkidle')
            page.wait_for_function("document.getElementById('f-count').textContent !== '—'", timeout=20000)
            page.wait_for_timeout(900)
        def count(): return int(page.locator('#f-count').inner_text().replace(',',''))
        def slider(name,value): page.locator(name).evaluate('(e,v)=>{e.value=v;e.dispatchEvent(new Event("input",{bubbles:true}))}',str(value))
        load()
        assert count()==meta['n'], (count(),meta['n'])
        assert 'Built' in page.locator('#f-sources').inner_text()
        assert meta['generated_at'] in page.locator('#f-edition').inner_text()
        for layout in ['clock','grid','cna','vendor','cwe','status']:
            page.locator(f'[data-layout={layout}]').click();page.wait_for_timeout(850)
            if layout in ['grid','cna','vendor','cwe','status']:
                group_counts=page.locator('.f-label.group').evaluate_all("els => els.map(e => [...e.childNodes].filter(n => n.nodeType === Node.TEXT_NODE).map(n => n.textContent).join(''))")
                import re
                total=sum(int(re.search(r'([\d,]+)(?: · KEV|$)',text).group(1).replace(',','')) for text in group_counts)
                assert count()==total,(layout,count(),total)
            if synthetic and layout=='cna':
                before=set(page.locator('.f-label.group b').all_text_contents())
                page.locator('#f-sort').select_option('name')
                assert set(page.locator('.f-label.group b').all_text_contents())==before
        page.locator('[data-layout=time]').click();page.wait_for_timeout(850)
        if synthetic:
            page.locator('#f-select').click()
            box=page.locator('#f-canvas').bounding_box()
            page.mouse.move(box['x']+2,box['y']+2);page.mouse.down()
            page.mouse.move(box['x']+box['width']-2,box['y']+box['height']-2,steps=10);page.mouse.up()
            assert page.locator('#f-sel').is_visible() and count()==meta['n']
            page.locator('#f-sel-clear').click();page.locator('#f-select').click()
        page.locator('#f-select-shown').click(); assert count()==meta['n']
        slider('#f-asof',0);assert page.locator('#f-sel').is_hidden()
        if synthetic:
            assert count()==0
            assert page.locator('#f-empty').is_visible()
            page.locator('#f-empty-reset').click()
        else:
            assert count()<=meta['n']
            page.locator('#f-reset-filters').click()
        assert count()==meta['n']
        slider('#f-size',2);assert 'z=2' in page.url
        load('#z=2');assert page.locator('#f-size').input_value()=='2'
        if synthetic:
            page.locator('#f-cna').fill('Median');page.wait_for_timeout(1100)
            assert count()==2
            page.locator('#f-select-shown').click()
            assert 'median 6.0' in page.locator('#f-sel').inner_text()
            assert '1 · 50.0 % of 2' in page.locator('#f-sel').inner_text()
            page.locator('#f-results-toggle').click()
            assert page.locator('#f-result-rows tr').count()==2
            page.locator('[data-record]').first.focus(); page.keyboard.press('Enter')
            assert page.locator('#f-inspector').is_visible()
            assert 'score added or changed' in page.locator('#f-record-detail').inner_text()
            page.locator('#f-inspector-close').click()
            with page.expect_download() as dl: page.locator('#f-export').click()
            receipt=json.loads(Path(dl.value.path()).read_text())
            assert receipt['count']==2 and len(receipt['records'])==2
            assert receipt['edition']==meta['generated_at']
            page.locator('#f-results-close').click()
            page.locator('#f-reset-filters').click()
            page.locator('#f-record').fill('CVE-2026-1001');page.keyboard.press('Enter')
            assert count()==1 and page.locator('#f-inspector').is_visible()
            page.locator('#f-inspector-close').click();page.locator('#f-reset-filters').click()
        page.locator('#f-flat').click();assert page.locator('#f-flat').get_attribute('aria-pressed')=='true'
        page.locator('#f-canvas').focus(); page.keyboard.press('ArrowLeft'); page.keyboard.press('Home')
        page.wait_for_timeout(1000); before=page.evaluate('window.fieldFrames');page.wait_for_timeout(400)
        assert page.evaluate('window.fieldFrames')==before,'Field keeps rendering while idle'
        if screenshots:
            screenshots.mkdir(parents=True,exist_ok=True);page.screenshot(path=str(screenshots/'field-desktop.png'))
        page.set_viewport_size({'width':390,'height':844});page.wait_for_timeout(400)
        assert page.evaluate('document.documentElement.scrollWidth')==390
        assert page.locator('#f-canvas').bounding_box()['height']>120
        page.locator('#f-controls-toggle').click();assert page.locator('#f-record').is_visible()
        page.locator('#f-controls-toggle').click()
        if screenshots:page.screenshot(path=str(screenshots/'field-mobile.png'))
        assert not errors,errors
        broken=browser.new_page();missing=[];broken.on('pageerror',lambda e:missing.append(str(e)))
        broken.route('**/three.min.js',lambda route:route.abort())
        broken.goto(base+'/field.html',wait_until='networkidle')
        assert '3D library did not load' in broken.locator('#f-notice').inner_text()
        assert not missing,missing
        corrupt=browser.new_page()
        corrupt.route('**/*.bin.gz',lambda route:route.fulfill(body=b'invalid',content_type='application/gzip'))
        corrupt.goto(base+'/field.html',wait_until='networkidle')
        assert 'checksum mismatch' in corrupt.locator('#f-notice').inner_text()
        browser.close()
    print(f'Field browser checks passed ({"fixture" if synthetic else "assembled site"}, {meta["n"]:,} records).')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site',type=Path)
    parser.add_argument('--screenshots',type=Path)
    parser.add_argument('--allow-sample',action='store_true',help='For isolated visual tests only')
    args=parser.parse_args()
    if args.site:check(args.site.resolve(),False,args.screenshots,args.allow_sample)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            site=Path(tmp)/'site';fixture(site);check(site,True,args.screenshots)
