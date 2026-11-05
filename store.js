/* Xag-ng :: c2/store.js — Durable Object state, long-poll, SSE fanout */
const MAX_LOG = 800;

export class Device {
  constructor(state, env) {
    this.state = state; this.env = env;
    this.data = null; this.waiters = []; this.subs = new Set();
  }
  async load() {
    if (this.data) return this.data;
    this.data = (await this.state.storage.get('d')) ||
      { uid: null, first: null, last: null, boots: 0, frames: [], queue: [], inflight: {},
        results: [], events: [], seq: 0, cfg: {}, meta: {} };
    return this.data;
  }
  async save() { await this.state.storage.put('d', this.data); }
  notify() { const w = this.waiters.splice(0, this.waiters.length); for (const r of w) r(); }
  sleep(ms) {
    return new Promise(res => {
      const t = setTimeout(() => { const i = this.waiters.indexOf(f); if (i >= 0) this.waiters.splice(i, 1); res(); }, ms);
      const f = () => { clearTimeout(t); res(); };
      this.waiters.push(f);
    });
  }
  emit(kind, body) {
    const ev = { seq: ++this.data.seq, ts: Date.now(), kind, body };
    push(this.data.events, ev, MAX_LOG);
    for (const s of this.subs) { try { s(ev); } catch (e) {} }
    return ev;
  }
  take() {
    const tasks = this.data.queue.splice(0, this.data.queue.length);
    for (const t of tasks) this.data.inflight[t.id] = { task: t, at: Date.now() };
    return tasks;
  }
  async rpc(op, args, timeout) {
    const id = crypto.randomUUID();
    this.data.queue.push({ id, op, args: args || {}, ts: Date.now() });
    this.notify();
    const t0 = Date.now();
    while (Date.now() - t0 < (timeout || 30000)) {
      const hit = this.data.results.find(r => r.id === id);
      if (hit) return { ok: true, id, result: hit.body.result };
      await this.sleep(250);
    }
    return { ok: false, id, err: 'timeout' };
  }

  async fetch(req) {
    const url = new URL(req.url);
    const d = await this.load();
    const now = Date.now();
    switch (url.pathname) {
      case '/ingest': {
        const b = await req.json();
        d.uid = d.uid || b.uid; d.first = d.first || now; d.last = now;
        if (b.boot) { d.boots++; this.emit('boot', { uid: b.uid }); }
        if (b.batch) for (const f of b.batch) { push(d.frames, f, MAX_LOG); this.emit('frame', f); }
        if (b.meta) d.meta = Object.assign(d.meta, b.meta);
        await this.save();
        this.env.REGISTRY.get(this.env.REGISTRY.idFromName('root'))
          .fetch('https://do/touch', { method: 'POST', body: JSON.stringify({ uid: d.uid, last: now }) })
          .catch(() => {});
        return json({ ok: true });
      }
      case '/poll': {
        const b = await req.json().catch(() => ({}));
        d.last = now;
        d.inflight = d.inflight || {};
        for (const [id, rec] of Object.entries(d.inflight)) {
          if (now - rec.at > 60000) { d.queue.push(rec.task); delete d.inflight[id]; }
        }
        let tasks = this.take();
        const wait = Math.min(Number(b.wait) || 0, 25000);
        if (!tasks.length && wait) {
          const t0 = Date.now();
          while (!tasks.length && Date.now() - t0 < wait) {
            await this.sleep(Math.min(250, wait - (Date.now() - t0)));
            tasks = this.take();
          }
        }
        await this.save();
        return json({ ok: true, now, tasks, cfg: d.cfg, depth: d.queue.length });
      }
      case '/rpc': {
        const b = await req.json();
        const r = await this.rpc(b.op, b.args, b.timeout);
        await this.save();
        return json(r);
      }
      case '/result': {
        d.inflight = d.inflight || {};
        for (const r of (await req.json()).results || []) {
          if (r && r.id) delete d.inflight[r.id];
          push(d.results, { ts: now, id: r && r.id, body: r }, MAX_LOG);
          this.emit('result', r);
        }
        await this.save();
        return json({ ok: true });
      }
      case '/enqueue': {
        const t = await req.json();
        const id = t.id || crypto.randomUUID();
        d.queue.push({ id, op: t.op, args: t.args || {}, ts: now });
        this.notify();
        this.emit('task', { id, op: t.op });
        await this.save();
        return json({ ok: true, id, depth: d.queue.length });
      }
      case '/cfg': { d.cfg = Object.assign(d.cfg, await req.json()); await this.save(); return json({ ok: true, cfg: d.cfg }); }
      case '/state': return json({ uid: d.uid, first: d.first, last: d.last, boots: d.boots,
        depth: d.queue.length, inflight: Object.keys(d.inflight || {}).length,
        frames: d.frames.length, results: d.results.length, meta: d.meta });
      case '/log': {
        const kind = url.searchParams.get('kind') || 'frames';
        const since = Number(url.searchParams.get('since') || 0);
        return json({ ok: true, rows: (d[kind] || []).filter(r => (r.ts || r.t || 0) > since).slice(-MAX_LOG) });
      }
      case '/events': {
        const since = Number(url.searchParams.get('since') || 0);
        const wait = Math.min(Number(url.searchParams.get('wait') || 0), 25000);
        let rows = d.events.filter(e => e.seq > since);
        if (!rows.length && wait) {
          const t0 = Date.now();
          while (!rows.length && Date.now() - t0 < wait) {
            await this.sleep(250);
            rows = d.events.filter(e => e.seq > since);
          }
        }
        return json({ ok: true, seq: d.seq, rows });
      }
      case '/live': {
        const since = Number(url.searchParams.get('since') || 0);
        const enc = new TextEncoder();
        const self_ = this;
        let ctrl = null, hb = null, life = null, closed = false;
        const send = (ev) => {
          if (closed || !ctrl) return;
          try { ctrl.enqueue(enc.encode('data: ' + JSON.stringify(ev) + '\n\n')); } catch (e) {}
        };
        const stream = new ReadableStream({
          start(c) {
            ctrl = c;
            for (const ev of self_.data.events.filter(e => e.seq > since)) send(ev);
            self_.subs.add(send);
            hb = setInterval(() => send({ seq: 0, ts: Date.now(), kind: 'hb', body: {} }), 15000);
            life = setTimeout(() => { if (!closed) { closed = true; clearInterval(hb); self_.subs.delete(send); try { ctrl.close(); } catch (e) {} } }, 110000);
          },
          cancel() {
            closed = true; clearInterval(hb); clearTimeout(life); self_.subs.delete(send);
          }
        });
        return new Response(stream, { headers: {
          'content-type': 'text/event-stream', 'cache-control': 'no-store', 'connection': 'keep-alive'
        }});
      }
      default: return json({ ok: false }, 404);
    }
  }
}

export class Registry {
  constructor(state) { this.state = state; }
  async fetch(req) {
    const url = new URL(req.url);
    const i = (await this.state.storage.get('i')) || {};
    if (url.pathname === '/touch') { const { uid, last } = await req.json(); i[uid] = last; await this.state.storage.put('i', i); return json({ ok: true }); }
    if (url.pathname === '/list') return json({ ok: true, devices: Object.entries(i).map(([uid, last]) => ({ uid, last })).sort((a, b) => b.last - a.last) });
    return json({ ok: false }, 404);
  }
}

function push(a, x, cap) { a.push(x); if (a.length > cap) a.splice(0, a.length - cap); }
function json(o, s = 200) { return new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } }); }
