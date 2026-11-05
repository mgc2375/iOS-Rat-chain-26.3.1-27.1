import hmac, hashlib, json, urllib.request, urllib.parse, time, os

U = ""
TOKEN = os.environ.get("XG_ADMIN", "")
KEY = os.environ.get("XG_KEY") or TOKEN
UID = "TESTDEV-" + time.strftime("%Y%m%d-%H%M%S")

def sign(raw):
    ts = str(int(time.time() * 1000))
    sig = hmac.new(KEY.encode(), (UID + ":" + ts + ":" + raw.decode()).encode(), hashlib.sha256).hexdigest()
    return {"x-xg-uid": UID, "x-xg-ts": ts, "x-xg-sig": sig}

def post(path, obj):
    raw = json.dumps(obj).encode()
    h = {"content-type": "application/json", "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"}
    if isinstance(obj, dict) and "uid" in obj:
        h.update(sign(raw))
    req = urllib.request.Request(U + path, data=raw, headers=h, method="POST")
    return json.load(urllib.request.urlopen(req))

def get(path):
    q = urllib.parse.urlencode({"token": TOKEN})
    print("   get url:", U + path + "?" + q)
    req = urllib.request.Request(U + path + "?" + q, headers={"x-xg-uid": UID, "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"}, method="GET")
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return "HTTP " + str(e.code) + " body=" + e.read().decode()

print("uid:", UID)
print("1) boot beacon:", post("/up", {"uid": UID, "boot": 1, "batch": [{"op": "boot", "t": int(time.time()*1000), "seq": 1, "result": "ok", "data": {"ua": "test-agent", "uid": UID}}]}))
print("2) poll (empty):", post("/poll", {"uid": UID, "wait": 100}))
# 3) operator enqueue a boot task via POST with token in query
def admin_post(path):
    q = urllib.parse.urlencode({"token": TOKEN})
    full = path if "?" in path else path + "?" + q
    print("   admin_post url:", U + full)
    req = urllib.request.Request(U + full,
        data=json.dumps({"op": "boot", "args": {}}).encode(), headers={"x-xg-uid": UID, "content-type": "application/json", "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"}, method="POST")
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return "HTTP " + str(e.code) + " body=" + e.read().decode()

print("3) enqueue boot task:", admin_post("/admin/task?uid=" + urllib.parse.quote(UID) + "&token=" + TOKEN))
print("3b) list via get():", get("/admin/list"))
time.sleep(1)
print("4) device list:", get("/admin/list"))
print("5) device state:", get("/admin/state"))
log = get("/admin/log")
print("6) frames:", json.dumps(log, indent=2)[:600])
