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

    jingle = app[app.index('let startupJingleAttempted'):app.index('function escapeHtml(')]
    fixture = directory / 'startup-audio.html'
    fixture.write_text('<body><script>const state={bootstrap:{mode:"simulation"}};'
        + jingle + '''
        (async()=>{
          const timers=[];window.setTimeout=f=>timers.push(f);
          let made=0,closed=0,notes=[],fail=false,pending=false,lateResume;
          const gain={setValueAtTime(){},linearRampToValueAtTime(value){if(value>0.05)throw Error('too loud');}};
          class Audio {constructor(){made++;this.state='running';this.currentTime=0;this.destination={};if(fail==='constructor')throw Error('no device');}
            resume(){return pending?new Promise(resolve=>lateResume=resolve):fail?Promise.reject(Error('unavailable')):Promise.resolve();}
            close(){closed++;return Promise.resolve();}
            createGain(){return {gain,connect(){}};}
            createOscillator(){const frequency={};return {frequency,connect(){},start(at){notes.push({frequency:frequency.value,at});},stop(at){if(at>1)throw Error('too long');}};}}
          window.AudioContext=Audio;
          const check=(ok,message)=>{if(!ok)throw Error(message);};
          playStartupJingle();check(made===0,'simulation must stay silent');
          state.bootstrap.mode='live';
          Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});
          playStartupJingle();check(made===0,'hidden page must stay silent');
          Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'});
          state.bootstrap.mode='live';playStartupJingle();playStartupJingle();
          await Promise.resolve();check(made===1&&notes.length===4,'one brief jingle');
          check(new Set(notes.map(n=>n.frequency)).size===4,'original rising notes');
          timers.splice(0).forEach(f=>f());check(closed===1,'bounded cleanup');
          for(const failure of ['constructor','resume','pending','missing']) {
            startupJingleAttempted=false;fail=failure;pending=failure==='pending';
            window.AudioContext=failure==='missing'?undefined:Audio;
            const before=notes.length;playStartupJingle();
            await Promise.resolve();await Promise.resolve();
            timers.splice(0).forEach(f=>f());
            if(failure==='pending'){lateResume();await Promise.resolve();}
            check(notes.length===before,'silent fallback '+failure);
          }
          const o=document.createElement('output');o.id='result';o.textContent='PASS once/live-only/brief/quiet/rejected/missing/pending/cleanup';document.body.append(o);
        })().catch(error=>{const o=document.createElement('output');o.id='result';o.textContent='FAIL '+error;document.body.append(o);});
        </script>''')
    run = subprocess.run(['google-chrome', '--headless=new', '--no-sandbox',
        '--disable-gpu', f'--user-data-dir={directory / "audio"}',
        '--virtual-time-budget=1000', '--dump-dom', fixture.as_uri()],
        capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    match = re.search(r'<output id="result">(.*?)</output>', run.stdout)
    assert match and match[1].startswith('PASS'), run.stdout
    print('Startup audio behavior ' + match[1] + ' (mock device; not audible playback)')

    # Real Chromium Web Audio synthesis, offline: verify the produced waveform
    # without playing sound on the user's computer or claiming a physical sink.
    fixture = directory / 'startup-waveform.html'
    fixture.write_text('<body><script>const state={bootstrap:{mode:"live"}};'
        + jingle + '''
        let context;
        class RenderAudio extends OfflineAudioContext {
          constructor(){super(1,44100,44100);context=this;}
          get state(){return 'running';}
          resume(){return Promise.resolve();}
          close(){return Promise.resolve();}
        }
        window.AudioContext=RenderAudio;
        playStartupJingle();
        Promise.resolve().then(()=>context.startRendering()).then(buffer=>{
          const samples=buffer.getChannelData(0);
          let peak=0,last=0,energy=0;
          samples.forEach((v,i)=>{peak=Math.max(peak,Math.abs(v));energy+=v*v;if(Math.abs(v)>0.00001)last=i;});
          const result={peak,energy,lastSeconds:last/44100};
          if(!(peak>0.02&&peak<0.09&&energy>1&&result.lastSeconds<0.85))throw Error(JSON.stringify(result));
          const o=document.createElement('output');o.id='result';o.textContent='PASS '+JSON.stringify(result);document.body.append(o);
        }).catch(error=>{const o=document.createElement('output');o.id='result';o.textContent='FAIL '+error;document.body.append(o);});
        </script>''')
    run = subprocess.run(['google-chrome', '--headless=new', '--no-sandbox',
        '--disable-gpu', f'--user-data-dir={directory / "waveform"}',
        '--virtual-time-budget=3000', '--dump-dom', fixture.as_uri()],
        capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    match = re.search(r'<output id="result">(.*?)</output>', run.stdout)
    assert match and match[1].startswith('PASS'), run.stdout
    print('Real offline Web Audio waveform ' + match[1] + ' (no physical playback claim)')

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
