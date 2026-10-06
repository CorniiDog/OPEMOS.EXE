"""Render the actual completion function and stylesheet; never call power APIs."""
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
