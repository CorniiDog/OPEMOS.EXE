"""Render shipped UI controls without calling power, folder, or imaging APIs."""
import json
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
app = (root / 'builder/welcome/app.js').read_text()
css = (root / 'builder/welcome/app.css').read_text()
button = app[app.index('function button('):app.index('function formatBytes(')]
completion = app[app.index('function completionScreen('):app.index('async function power(')]
with tempfile.TemporaryDirectory(prefix='opemos-completion-render-') as temporary:
    directory = pathlib.Path(temporary)
    for width in (1280, 640):
        fixture = directory / f'completion-{width}.html'
        fixture.write_text('<style>' + css + '</style><main id="view"></main><script>'
            + 'const view=document.querySelector("#view");' + button + completion
            + '''completionScreen(); const row=document.querySelector('.completion-actions');const r=row.getBoundingClientRect();const b=[...row.querySelectorAll('button')].map(e=>{const x=e.getBoundingClientRect();return {label:e.textContent,x:x.x,y:x.y,right:x.right};});const o=document.createElement('output');o.id='result';o.textContent=JSON.stringify({left:r.left,buttons:b});document.body.append(o);</script>''')
        run = subprocess.run(['google-chrome', '--headless=new', '--no-sandbox',
            '--disable-gpu', f'--user-data-dir={directory / str(width)}',
            f'--window-size={width},800', '--virtual-time-budget=1000',
            '--dump-dom', fixture.as_uri()], capture_output=True, text=True, timeout=30)
        assert run.returncode == 0, run.stderr
        match = re.search(r'<output id="result">(.*?)</output>', run.stdout)
        assert match, run.stderr
        result = json.loads(match[1])
        buttons = result['buttons']
        assert [b['label'] for b in buttons] == ['Stay Here', 'Restart', 'Shut Down']
        assert abs(buttons[0]['x'] - result['left']) < 1, result
        assert max(b['y'] for b in buttons) - min(b['y'] for b in buttons) < 1, result
        for previous, current in zip(buttons, buttons[1:]):
            assert abs(current['x'] - previous['right'] - 5) < 0.5, result
        print(f'{width}px actual completion render PASS: {result}')

    # Reuse this contained browser-render check for the actual host markup/CSS.
    host_html = (root / 'src/index.html').read_text()
    host_css = (root / 'src/styles.css').read_text()
    output = host_html[host_html.index('<div class="source-choice export-choice"'):
                       host_html.index('<div class="build-side-column"')]
    nvidia = re.search(r'<label class="source-choice nvidia-choice".*?</label>',
                       host_html, re.S).group(0)
    for width in (1280, 640):
        for custom in (False, True):
            fixture = directory / f'output-{width}-{custom}.html'
            setup = '''document.querySelector('#output-folder-label').textContent='/a/very-long-selected-folder/'.repeat(12);document.querySelector('#reset-output-folder').classList.remove('hidden');''' if custom else ''
            fixture.write_text('<style>' + host_css + '</style><div class="build-options-grid">'
                + output + '<div class="build-side-column">' + nvidia + '</div></div><script>'
                + setup + '''const outer=document.querySelector('.export-choice'),inner=document.querySelector('.output-destination'),other=document.querySelector('.nvidia-choice');const rect=e=>{const r=e.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,right:r.right};};const o=document.createElement('output');o.id='result';o.textContent=JSON.stringify({outer:rect(outer),other:rect(other),innerBorder:getComputedStyle(inner).borderTopWidth,innerBackground:getComputedStyle(inner).backgroundColor,resetVisible:document.querySelector('#reset-output-folder').getBoundingClientRect().width>0,buttons:[...inner.querySelectorAll('button')].filter(e=>e.getBoundingClientRect().width>0).map(rect),scroll:document.documentElement.scrollWidth,viewport:innerWidth});document.body.append(o);</script>''')
            run = subprocess.run(['google-chrome', '--headless=new', '--no-sandbox',
                '--disable-gpu', f'--user-data-dir={directory / f"output-{width}-{custom}"}',
                f'--window-size={width},800', '--dump-dom', fixture.as_uri()],
                capture_output=True, text=True, timeout=30)
            assert run.returncode == 0, run.stderr
            match = re.search(r'<output id="result">(.*?)</output>', run.stdout)
            assert match, run.stderr
            result = json.loads(match[1])
            assert result['innerBorder'] == '0px', result
            assert result['innerBackground'] == 'rgba(0, 0, 0, 0)', result
            assert result['resetVisible'] == custom, result
            assert result['scroll'] <= result['viewport'], result
            if width > 680:
                assert abs(result['outer']['width'] - result['other']['width']) < 1, result
                assert abs(result['outer']['y'] - result['other']['y']) < 1, result
            else:
                assert result['other']['y'] > result['outer']['y'], result
            for button_rect in result['buttons']:
                assert button_rect['x'] >= result['outer']['x'], result
                assert button_rect['right'] <= result['outer']['right'], result
            print(f'{width}px output folder custom={custom} render PASS: {result}')
