"""OnStar Token Helper

Gets a fresh GM/OnStar sign-in token for the BigThunderSR OnStar2MQTT
Home Assistant add-on when the add-on's own automated sign-in is blocked
("Access Denied").

How it works
  1. Opens GM's real sign-in page in your normal browser. You sign in by hand,
     so GM's bot detection sees a person, not a script. The tool never sees
     your GM password.
  2. GM redirects to msauth.com.gm.mychevrolet://auth?code=...  The tool
     registers itself (current user only) as the handler for that link, so it
     receives the one-time code.
  3. It trades the code for a token set (PKCE), the same way the
     metheos/onstar_firefox extension does.
  4. It serves the token once, over your LAN, to Home Assistant's built-in
     Downloader integration, which saves it to /share/<folder>/microsoft_tokens.json.
  5. It starts the add-on and watches its log. If the add-on falls back to its
     own automated sign-in, the tool stops it at once so GM's block isn't made worse.

The token is kept in memory only; it is never written to this PC's disk.
"""

import base64
import ctypes
import ctypes.wintypes
import hashlib
import http.server
import json
import os
import queue
import secrets
import socket
import sys
import threading
import time
import tkinter as tk
import urllib.parse
import urllib.request
import webbrowser
import winreg
from tkinter import messagebox, simpledialog, ttk

APP = "OnStar Token Helper"
APP_DIR = os.path.join(os.environ["LOCALAPPDATA"], "OnStarTokenHelper")
SETTINGS = os.path.join(APP_DIR, "settings.json")
CALLBACK = os.path.join(APP_DIR, "callback.txt")

SCHEME = "msauth.com.gm.mychevrolet"
CLIENT_ID = "3ff30506-d242-4bed-835b-422bf992622e"
REDIRECT_URI = SCHEME + "://auth"
DISCOVERY = ("https://custlogin.gm.com/gmb2cprod.onmicrosoft.com"
             "/b2c_1a_seamless_mobile_signuporsignin/v2.0/.well-known/openid-configuration")
SCOPE = f"https://gmb2cprod.onmicrosoft.com/{CLIENT_ID}/Test.Read openid profile offline_access"

DEFAULT_PORT = 8766
FIREWALL_RULE = "OnStar Token Helper"
# Log lines that mean the add-on is attempting its own (blockable) browser sign-in.
FALLBACK_MARKERS = ("Starting Xvfb", "Access Denied", "different user", "Performing full authentication")


# ── Windows helpers ─────────────────────────────────────────────────────────

class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    """Encrypt/decrypt with Windows DPAPI (only this Windows user can read it)."""
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    src = _Blob(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_char)))
    out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if not fn(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def register_scheme():
    """Make GM's app link open this tool (HKCU only, no admin needed)."""
    exe = sys.executable.replace("python.exe", "pythonw.exe")
    cmd = f'"{exe}" -I "{os.path.abspath(__file__)}" "%1"'
    base = rf"Software\Classes\{SCHEME}"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
        winreg.SetValueEx(k, None, 0, winreg.REG_SZ, f"URL:{APP}")
        winreg.SetValueEx(k, "URL Protocol", 0, winreg.REG_SZ, "")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\shell\open\command") as k:
        winreg.SetValueEx(k, None, 0, winreg.REG_SZ, cmd)


def firewall_rule_exists() -> bool:
    import subprocess
    r = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={FIREWALL_RULE}"],
                       capture_output=True, text=True, creationflags=0x08000000)
    return r.returncode == 0 and FIREWALL_RULE in r.stdout


def add_firewall_rule(port: int, ha_ip: str):
    """Ask Windows (UAC prompt) to allow ONLY the HA box to reach our one port."""
    args = (f'advfirewall firewall add rule name="{FIREWALL_RULE}" dir=in action=allow '
            f'protocol=TCP localport={port} remoteip={ha_ip}')
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "netsh", args, None, 0)


# ── Settings ────────────────────────────────────────────────────────────────

def load_settings() -> dict:
    try:
        with open(SETTINGS, encoding="utf-8") as f:
            s = json.load(f)
        s["ha_token"] = _dpapi(base64.b64decode(s.pop("ha_token_dpapi")), False).decode()
        return s
    except (OSError, KeyError, ValueError):
        return {}


def save_settings(s: dict):
    os.makedirs(APP_DIR, exist_ok=True)
    out = {k: v for k, v in s.items() if k != "ha_token"}
    out["ha_token_dpapi"] = base64.b64encode(_dpapi(s["ha_token"].encode(), True)).decode()
    with open(SETTINGS, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)


# ── Home Assistant ──────────────────────────────────────────────────────────

class HA:
    def __init__(self, url: str, token: str):
        self.url, self.token = url.rstrip("/"), token

    def rest(self, path, body=None, method=None):
        req = urllib.request.Request(self.url + path, method=method or ("POST" if body is not None else "GET"),
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer " + self.token,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except ValueError:
            return raw

    def supervisor(self, endpoint, method="get", data=None):
        """Supervisor API through HA's WebSocket (the REST proxy refuses user tokens)."""
        import asyncio
        import websockets

        async def go():
            ws_url = self.url.replace("http", "ws", 1) + "/api/websocket"
            async with websockets.connect(ws_url, max_size=None) as w:
                await w.recv()
                await w.send(json.dumps({"type": "auth", "access_token": self.token}))
                if json.loads(await w.recv()).get("type") != "auth_ok":
                    raise RuntimeError("Home Assistant rejected the access token")
                msg = {"id": 1, "type": "supervisor/api", "endpoint": endpoint, "method": method}
                if data is not None:
                    msg["data"] = data
                await w.send(json.dumps(msg))
                while True:
                    r = json.loads(await w.recv())
                    if r.get("id") == 1:
                        if not r.get("success"):
                            raise RuntimeError(f"Supervisor {endpoint}: {r.get('error')}")
                        return r.get("result")
        return asyncio.run(go())

    def addon_log_tail(self, slug, n=60):
        return str(self.rest(f"/api/hassio/addons/{slug}/logs")).splitlines()[-n:]


# ── GM sign-in (PKCE) ───────────────────────────────────────────────────────

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt_claims(token: str) -> dict:
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except (IndexError, ValueError):
        return {}


def start_gm_flow():
    with urllib.request.urlopen(DISCOVERY, timeout=30) as r:
        cfg = json.load(r)
    verifier = b64url(secrets.token_bytes(32))
    state = b64url(secrets.token_bytes(16))
    params = {
        "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": SCOPE,
        "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256", "state": state,
        "bundleID": "com.gm.myChevrolet", "channel": "lightreg", "ui_locales": "en-US", "brand": "chevrolet",
    }
    return cfg["authorization_endpoint"] + "?" + urllib.parse.urlencode(params), cfg["token_endpoint"], verifier, state


def exchange_code(token_endpoint, code, verifier) -> dict:
    body = urllib.parse.urlencode({"grant_type": "authorization_code", "client_id": CLIENT_ID,
                                   "redirect_uri": REDIRECT_URI, "code": code,
                                   "code_verifier": verifier}).encode()
    req = urllib.request.Request(token_endpoint, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            t = json.load(r)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"GM refused the code ({e.code}): {detail[:300]}")
    # Shape OnStarJS expects in microsoft_tokens.json (see GMAuth.loadMSToken).
    now = int(time.time())
    t["expires_at"] = now + int(t.get("expires_in", 3600))
    rt_life = t.get("refresh_token_expires_in")
    if rt_life:
        t["refresh_expires_in"] = int(rt_life)
        t["refresh_expires_at"] = now + int(rt_life)
    t["refresh_obtained_at"] = now
    return t


# ── One-shot LAN file server ────────────────────────────────────────────────

def serve_once(payload: bytes, port: int, allowed_ip: str, path: str, done: threading.Event):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.client_address[0] != allowed_ip or self.path != path:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            done.set()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("0.0.0.0", port), H)
    srv.timeout = 1
    end = time.time() + 120
    while not done.is_set() and time.time() < end:
        srv.handle_request()
    srv.server_close()


# ── GUI ─────────────────────────────────────────────────────────────────────

class App:
    def __init__(self, root):
        self.root = root
        root.title(APP)
        root.geometry("640x420")
        self.q = queue.Queue()
        self.text = tk.Text(root, wrap="word", font=("Segoe UI", 10), state="disabled")
        self.text.pack(fill="both", expand=True, padx=10, pady=(10, 4))
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=10, pady=(0, 10))
        self.go = ttk.Button(bar, text="Sign in to GM and fix the add-on", command=self.start)
        self.go.pack(side="left")
        ttk.Button(bar, text="Settings", command=self.settings_dialog).pack(side="left", padx=8)
        ttk.Button(bar, text="Close", command=root.destroy).pack(side="right")
        root.after(200, self.pump)
        self.s = load_settings()
        self.say("This gets a new OnStar sign-in for your Home Assistant add-on.\n"
                 "You will sign in to GM in your own browser; this tool never sees your GM password.\n")
        if not self.s:
            root.after(300, self.settings_dialog)

    # thread-safe UI helpers
    def say(self, msg):
        self.q.put(("say", msg))

    def pump(self):
        while not self.q.empty():
            kind, val = self.q.get()
            if kind == "say":
                self.text.configure(state="normal")
                self.text.insert("end", val + "\n")
                self.text.see("end")
                self.text.configure(state="disabled")
            elif kind == "ask":
                msg, holder, ev = val
                holder.append(messagebox.askyesno(APP, msg, parent=self.root))
                ev.set()
            elif kind == "done":
                self.go.configure(state="normal")
        self.root.after(200, self.pump)

    def ask(self, msg) -> bool:
        holder, ev = [], threading.Event()
        self.q.put(("ask", (msg, holder, ev)))
        ev.wait()
        return holder[0]

    def settings_dialog(self):
        s = dict(self.s)
        url = simpledialog.askstring(APP, "Home Assistant address (e.g. http://192.168.x.x or http://homeassistant.local:8123):",
                                     initialvalue=s.get("ha_url", "http://"), parent=self.root)
        if not url:
            return
        tok = simpledialog.askstring(APP, "Home Assistant long-lived access token\n"
                                     "(HA > your profile > Security > Long-lived access tokens > Create).\n"
                                     "Leave blank to keep the saved one.", show="*", parent=self.root)
        if tok:
            s["ha_token"] = tok.strip()
        if not s.get("ha_token"):
            return
        s["ha_url"] = url.strip().rstrip("/")
        try:
            ha = HA(s["ha_url"], s["ha_token"])
            addons = [a for a in ha.supervisor("/addons")["addons"] if "onstar" in a["slug"].lower()]
        except Exception as e:
            messagebox.showerror(APP, f"Could not reach Home Assistant:\n{e}", parent=self.root)
            return
        if not addons:
            messagebox.showerror(APP, "No OnStar add-on found on that Home Assistant.", parent=self.root)
            return
        if len(addons) == 1:
            s["addon_slug"] = addons[0]["slug"]
        else:
            names = "\n".join(f"{i + 1}. {a['name']}" for i, a in enumerate(addons))
            n = simpledialog.askinteger(APP, f"Which add-on?\n{names}", minvalue=1, maxvalue=len(addons),
                                        parent=self.root)
            if not n:
                return
            s["addon_slug"] = addons[n - 1]["slug"]
        s.setdefault("port", DEFAULT_PORT)
        s["share_folder"] = s.get("share_folder") or s["addon_slug"].split("_")[-1]  # e.g. "vehicle1"
        self.s = s
        save_settings(s)
        self.say(f"Settings saved. Add-on: {s['addon_slug']}")

    def start(self):
        if not self.s.get("addon_slug"):
            self.settings_dialog()
            if not self.s.get("addon_slug"):
                return
        self.go.configure(state="disabled")
        threading.Thread(target=self.run_safe, daemon=True).start()

    def run_safe(self):
        try:
            self.run()
        except Exception as e:
            self.say(f"\nSTOPPED: {e}")
        finally:
            self.q.put(("done", None))

    # the actual job
    def run(self):
        s = self.s
        ha = HA(s["ha_url"], s["ha_token"])
        slug, port = s["addon_slug"], int(s["port"])
        ha_ip = socket.gethostbyname(urllib.parse.urlparse(s["ha_url"]).hostname)
        token_dir = f"/share/{s['share_folder']}"

        # 1. Preflight
        self.say("Checking Home Assistant...")
        info = ha.supervisor(f"/addons/{slug}/info")
        loc = (info.get("options") or {}).get("TOKEN_LOCATION")
        if loc != token_dir:
            self.say(f"\nOne-time change needed in the add-on:\n"
                     f"  Settings > Add-ons > {info.get('name')} > Configuration\n"
                     f"  Set TOKEN_LOCATION to:  {token_dir}\n"
                     f"  Save (don't start it), then click the button here again.\n"
                     f"(Home Assistant can only drop files into /share, not {loc}.)")
            return
        if not any(e for e in ha.rest("/api/config/config_entries/entry") if e.get("domain") == "downloader"):
            self.say("Setting up Home Assistant's built-in Downloader (saves files into /share)...")
            flow = ha.rest("/api/config/config_entries/flow", {"handler": "downloader"})
            res = ha.rest(f"/api/config/config_entries/flow/{flow['flow_id']}", {"download_dir": "/share"})
            if res.get("type") != "create_entry":
                raise RuntimeError(f"Downloader setup failed: {res}")
        if not firewall_rule_exists():
            self.say("Windows will ask for permission to let ONLY Home Assistant fetch the file from this PC...")
            add_firewall_rule(port, ha_ip)
            for _ in range(60):
                time.sleep(1)
                if firewall_rule_exists():
                    break
            else:
                raise RuntimeError("Firewall rule was not added (permission declined?)")
        if info.get("state") == "started":
            self.say("Stopping the add-on while we work...")
            ha.supervisor(f"/addons/{slug}/stop", "post")

        # 2. GM sign-in in the user's browser
        register_scheme()
        try:
            os.remove(CALLBACK)
        except OSError:
            pass
        auth_url, token_endpoint, verifier, state = start_gm_flow()
        self.say("\nOpening GM's sign-in page in your browser.\n"
                 "Sign in normally. At the end your browser will ask to open\n"
                 f"'{APP}' (or pythonw) — allow it.")
        webbrowser.open(auth_url)
        end = time.time() + 600
        while not os.path.exists(CALLBACK):
            if time.time() > end:
                raise RuntimeError("No sign-in received within 10 minutes")
            time.sleep(1)
        time.sleep(0.3)
        with open(CALLBACK, encoding="utf-8") as f:
            cb = f.read().strip()
        os.remove(CALLBACK)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(cb).query)
        if "error" in qs:
            raise RuntimeError(f"GM returned an error: {qs.get('error_description', qs['error'])[0]}")
        if qs.get("state", [None])[0] != state:
            raise RuntimeError("Sign-in reply did not match this session; try again")
        tokens = exchange_code(token_endpoint, qs["code"][0], verifier)
        who = jwt_claims(tokens["access_token"])
        ident = who.get("email") or who.get("name") or "unknown"
        self.say(f"Signed in to GM as: {ident}")
        if not self.ask(f"GM sign-in worked for:\n\n{ident}\n\nThis must be the same account the add-on uses. Continue?"):
            raise RuntimeError("Cancelled")

        # 3. Hand the token to HA (served once to HA's IP only, then gone)
        self.say("Sending the token to Home Assistant...")
        path = "/" + secrets.token_urlsafe(24)
        done = threading.Event()
        srv = threading.Thread(target=serve_once, args=(json.dumps(tokens).encode(), port, ha_ip, path, done),
                               daemon=True)
        srv.start()
        my_ip = self._lan_ip(ha_ip)
        ha.rest("/api/services/downloader/download_file",
                {"url": f"http://{my_ip}:{port}{path}", "subdir": s["share_folder"],
                 "filename": "microsoft_tokens.json", "overwrite": True})
        srv.join(130)
        tokens = None
        if not done.is_set():
            raise RuntimeError("Home Assistant never fetched the file (firewall or network?)")
        time.sleep(3)
        self.say(f"Saved to {token_dir}/microsoft_tokens.json on Home Assistant.")

        # 4. Start the add-on and make sure it uses the token
        ha.supervisor(f"/addons/{slug}/options", "post", {"boot": "auto"})
        ha.supervisor(f"/addons/{slug}/start", "post")
        self.say("Add-on started. Watching it for 2 minutes...")
        for _ in range(24):
            time.sleep(5)
            tail = "\n".join(ha.addon_log_tail(slug, 80))
            if any(m in tail for m in FALLBACK_MARKERS):
                ha.supervisor(f"/addons/{slug}/stop", "post")
                ha.supervisor(f"/addons/{slug}/options", "post", {"boot": "manual"})
                raise RuntimeError("The add-on ignored the token and tried its own sign-in, so it was stopped "
                                   "(start on boot set to manual). Check the add-on log.")
            if ha.supervisor(f"/addons/{slug}/info").get("state") != "started":
                raise RuntimeError("The add-on stopped by itself. Check its log.")
        self.say("\nDONE. The add-on is running on the new token. Your car's entities should return within a few minutes.\n"
                 "The token renews itself; if GM blocks it again (often ~60 days), just run this again.")

    @staticmethod
    def _lan_ip(target):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 80))
            return s.getsockname()[0]
        finally:
            s.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1].lower().startswith(SCHEME):
        # Launched by the browser with GM's redirect: hand it to the waiting window.
        os.makedirs(APP_DIR, exist_ok=True)
        with open(CALLBACK, "w", encoding="utf-8") as f:
            f.write(sys.argv[1])
        return
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
