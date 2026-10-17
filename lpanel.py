#!/usr/bin/env python3
import base64
import getpass
import hashlib
import hmac
import http.server
import io
import json
import mimetypes
import os
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from pathlib import Path

VERSION = "1.1"
CONFIG_NAME = ".lpanel_local.json"
DATA_NAME = ".lpanel"
PUBLIC_DIR = "public_html"
ROOT = Path.cwd().resolve()
CONFIG_PATH = ROOT / CONFIG_NAME
DATA_DIR = ROOT / DATA_NAME
COOKIE = "lpanel_session"
SESSION_TTL = 12 * 3600

STATE = {
    "config": None,
    "cpu": None,
    "shell": None,
}


def eprint(*a):
    print(*a, file=sys.stderr, flush=True)


def now():
    return int(time.time())


def hash_password(password, salt=None, iterations=200000):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {"salt": salt.hex(), "hash": dk.hex(), "iterations": iterations}


def verify_password(password, pw):
    try:
        salt = bytes.fromhex(pw["salt"])
        iterations = int(pw["iterations"])
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk.hex(), pw["hash"])


def make_token(secret_hex, ttl=SESSION_TTL):
    secret = bytes.fromhex(secret_hex)
    exp = now() + ttl
    msg = str(exp).encode()
    sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def verify_token(token, secret_hex):
    try:
        exp_s, sig = token.split(".", 1)
        exp = int(exp_s)
    except Exception:
        return False
    if exp < now():
        return False
    secret = bytes.fromhex(secret_hex)
    expected = hmac.new(secret, exp_s.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def port_available(port, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ask_port(label, default, avoid=None):
    while True:
        try:
            raw = input(f"{label} [{default}]: ").strip()
        except EOFError:
            raw = ""
        if raw == "":
            value = default
        else:
            try:
                value = int(raw)
            except ValueError:
                print("  ! Port must be a number.")
                continue
        if not (1024 <= value <= 65535):
            print("  ! Port must be between 1024 and 65535.")
            continue
        if avoid is not None and value == avoid:
            print("  ! Panel and site ports must differ.")
            continue
        if not port_available(value):
            print(f"  ! Port {value} is already in use. Pick another.")
            continue
        return value


def ask_password():
    while True:
        try:
            p1 = getpass.getpass("Account password: ")
        except EOFError:
            return ""
        if len(p1) < 4:
            print("  ! Password must be at least 4 characters.")
            continue
        try:
            p2 = getpass.getpass("Confirm password: ")
        except EOFError:
            p2 = p1
        if p1 != p2:
            print("  ! Passwords do not match.")
            continue
        return p1


def setup_wizard(defaults=None):
    defaults = defaults or {}
    print()
    print("=" * 52)
    print(f"  lPanel {VERSION}  -  first run setup")
    print("=" * 52)
    panel_port = ask_port("Panel port", defaults.get("panel_port", 8080))
    site_port = ask_port("Site port", defaults.get("site_port", 8081), avoid=panel_port)
    try:
        account = input(f"Account name [{defaults.get('account', 'admin')}]: ").strip()
    except EOFError:
        account = ""
    if not account:
        account = defaults.get("account", "admin")
    print("(input hidden)")
    while True:
        password = ask_password()
        if password:
            break
        print("  ! Password required.")
    return {
        "panel_port": panel_port,
        "site_port": site_port,
        "account": account,
        "password": hash_password(password),
        "secret": secrets.token_hex(32),
        "created": now(),
    }


def save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def read_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json_file(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    tmp.replace(path)


def ensure_dirs():
    (ROOT / PUBLIC_DIR).mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)
    (DATA_DIR / "databases").mkdir(exist_ok=True)
    (DATA_DIR / "backups").mkdir(exist_ok=True)
    index = ROOT / PUBLIC_DIR / "index.html"
    if not index.exists():
        index.write_text(
            "<!doctype html>\n<html><head><meta charset=\"utf-8\">"
            "<title>It works</title></head>\n"
            "<body style=\"font-family:system-ui;background:#0f0f11;color:#ececf1;"
            "display:grid;place-items:center;height:100vh;margin:0\">\n"
            "<div style=\"text-align:center\"><h1>Your site is live</h1>"
            "<p style=\"color:#9a9aa5\">Served by lPanel from <code>public_html/</code></p></div>\n"
            "</body></html>\n",
            encoding="utf-8",
        )


def safe_path(rel):
    rel = (rel or "").lstrip("/\\")
    p = (ROOT / rel).resolve()
    if p != ROOT and ROOT not in p.parents:
        raise PermissionError("path escapes root")
    return p


def rel_of(p):
    try:
        return str(Path(p).resolve().relative_to(ROOT))
    except ValueError:
        return ""


def human_size(n):
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def is_internal(name):
    return name == CONFIG_NAME or name == DATA_NAME or name == "__pycache__"


def log_activity(action, detail="", client=""):
    entry = {"t": now(), "action": action, "detail": detail, "client": client}
    try:
        DATA_DIR.mkdir(exist_ok=True)
        with open(DATA_DIR / "activity.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass
    eprint(f"  [activity] {action} {detail}")


def read_activity(limit=200):
    path = DATA_DIR / "activity.log"
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    out.reverse()
    return out


def sysinfo():
    info = {"python": sys.version.split()[0], "version": VERSION, "root": str(ROOT), "cwd": os.getcwd()}
    try:
        info["cpus"] = os.cpu_count() or 1
        info["load"] = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        info["cpus"] = os.cpu_count() or 1
        info["load"] = [0, 0, 0]
    try:
        with open("/proc/uptime") as f:
            info["uptime"] = int(float(f.read().split()[0]))
    except OSError:
        info["uptime"] = 0
    try:
        du = shutil.disk_usage(str(ROOT))
        info["disk"] = {"total": du.total, "used": du.used, "free": du.free,
                        "total_h": human_size(du.total), "used_h": human_size(du.used),
                        "free_h": human_size(du.free),
                        "percent": round(du.used / du.total * 100, 1) if du.total else 0}
    except OSError:
        info["disk"] = None
    return info


def meminfo():
    total = avail = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) * 1024
                if total and avail:
                    break
    except OSError:
        pass
    used = max(total - avail, 0)
    return {"total": total, "used": used, "available": avail,
            "percent": round(used / total * 100, 1) if total else 0,
            "used_h": human_size(used), "total_h": human_size(total)}


def cpu_percent():
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()
    except OSError:
        return 0.0
    try:
        vals = [int(x) for x in parts[1:]]
    except ValueError:
        return 0.0
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    total = sum(vals)
    prev = STATE.get("cpu")
    STATE["cpu"] = (total, idle)
    if not prev:
        return 0.0
    dt = total - prev[0]
    di = idle - prev[1]
    if dt <= 0:
        return 0.0
    return round(max(0.0, min(100.0, 100.0 * (dt - di) / dt)), 1)


def metrics():
    return {"cpu": cpu_percent(), "mem": meminfo(), "load": sysinfo().get("load", [0, 0, 0])}


class ShellSession:
    def __init__(self, cwd, force_stateless=None):
        self.cwd = str(cwd)
        self.proc = None
        self.q = None
        self.lock = threading.Lock()
        if force_stateless is None:
            force_stateless = (os.name == "nt")
        self.stateless = bool(force_stateless)
        if not self.stateless:
            self.start()

    def start(self):
        if self.stateless:
            return
        self.stop()
        shell = shutil.which("bash") or shutil.which("sh")
        if not shell:
            self.stateless = True
            return
        self.proc = subprocess.Popen(
            [shell], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, cwd=self.cwd, bufsize=0,
        )
        self.q = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            buf = b""
            while True:
                chunk = self.proc.stdout.read(1)
                if not chunk:
                    break
                if chunk in (b"\n", b"\r"):
                    self.q.put(buf.decode("utf-8", "replace"))
                    buf = b""
                else:
                    buf += chunk
            if buf:
                self.q.put(buf.decode("utf-8", "replace"))
        except Exception:
            pass
        finally:
            if self.q is not None:
                self.q.put(None)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.kill()
            except OSError:
                pass

    def _run_stateless(self, command, timeout):
        stripped = command.strip()
        m = re.match(r'^cd(?:\s+(.+))?$', stripped, re.I)
        if m:
            target = (m.group(1) or "~").strip().strip('"').strip("'")
            target = os.path.expanduser(target)
            p = Path(target)
            newdir = (p if p.is_absolute() else Path(self.cwd) / p).resolve()
            if newdir.is_dir():
                self.cwd = str(newdir)
                return {"output": "", "cwd": self.cwd}
            return {"output": f"cd: no such directory: {target}", "cwd": self.cwd}
        try:
            r = subprocess.run(command, shell=True, cwd=self.cwd,
                               capture_output=True, text=True, timeout=timeout)
            out = (r.stdout or "") + (r.stderr or "")
        except subprocess.TimeoutExpired:
            out = "[timeout: command still running]"
        except Exception as e:
            out = f"error: {e}"
        if len(out) > 200000:
            out = out[:200000] + "\n... (truncated)"
        return {"output": out, "cwd": self.cwd}

    def run(self, command, timeout=60):
        if self.stateless:
            return self._run_stateless(command, timeout)
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                self.start()
            if self.stateless:
                return self._run_stateless(command, timeout)
            marker = "LPANEL_" + secrets.token_hex(8)
            try:
                self.proc.stdin.write((command + "\n").encode())
                self.proc.stdin.write(f'printf "\\n{marker}:%s\\n" "$PWD"\n'.encode())
                self.proc.stdin.flush()
            except (OSError, BrokenPipeError):
                self.start()
                return {"output": "shell restarted after error\n", "code": 1, "cwd": self.cwd}
            lines = []
            deadline = time.time() + timeout
            timed_out = True
            while time.time() < deadline:
                try:
                    line = self.q.get(timeout=max(0.1, deadline - time.time()))
                except queue.Empty:
                    break
                if line is None:
                    break
                if line.strip().startswith(marker):
                    rest = line.strip()[len(marker):]
                    if rest.startswith(":"):
                        self.cwd = rest[1:]
                    timed_out = False
                    break
                lines.append(line)
            out = "\n".join(lines)
            if len(out) > 200000:
                out = out[:200000] + "\n... (truncated)"
            if timed_out:
                out += "\n[timeout: command still running]"
            return {"output": out, "cwd": self.cwd}


def get_shell():
    if STATE.get("shell") is None:
        STATE["shell"] = ShellSession(ROOT)
    return STATE["shell"]


def parse_multipart(body, boundary):
    delim = b"--" + boundary
    out = []
    for chunk in body.split(delim)[1:]:
        if chunk in (b"", b"--", b"\r\n", b"--\r\n"):
            continue
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        if chunk.endswith(b"--"):
            chunk = chunk[:-2]
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]
        header_blob, sep, content = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        name = filename = None
        for line in header_blob.split(b"\r\n"):
            if line.lower().startswith(b"content-disposition"):
                text = line.decode("utf-8", "replace")
                m = re.search(r'name="([^"]*)"', text)
                if m:
                    name = m.group(1)
                m = re.search(r'filename="([^"]*)"', text)
                if m:
                    filename = m.group(1)
        out.append((name, filename, content))
    return out


def zip_paths(paths, arcnames=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, p in enumerate(paths):
            p = Path(p)
            arc = arcnames[i] if arcnames else p.name
            if p.is_dir():
                base = p
                added = False
                for item in sorted(base.rglob("*")):
                    rel = item.relative_to(base)
                    if item.is_dir():
                        zf.writestr(str(Path(arc) / rel).rstrip("/") + "/", "")
                    else:
                        try:
                            zf.write(item, str(Path(arc) / rel))
                        except OSError:
                            pass
                        added = True
                if not added:
                    zf.writestr(str(arc).rstrip("/") + "/", "")
            else:
                try:
                    zf.write(p, arc)
                except OSError:
                    pass
    buf.seek(0)
    return buf


def extract_zip(zf, dest):
    dest = Path(dest).resolve()
    for member in zf.namelist():
        target = (dest / member).resolve()
        if target != dest and dest not in target.parents:
            continue
        zf.extract(member, dest)


ROUTE_GET = {}
ROUTE_POST = {}


def route_get(path):
    def deco(fn):
        ROUTE_GET[path] = fn
        return fn
    return deco


def route_post(path):
    def deco(fn):
        ROUTE_POST[path] = fn
        return fn
    return deco


class BaseHandler(http.server.BaseHTTPRequestHandler):
    server_version = "lPanel"

    def log_message(self, fmt, *args):
        eprint(f"  {self.address_string()}  {fmt % args}")

    def read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def read_json(self):
        raw = self.read_body()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def send_bytes(self, data, ctype="application/octet-stream", status=200, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_json(self, obj, status=200):
        self.send_bytes(json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8", status=status)

    def send_text(self, text, status=200, ctype="text/plain; charset=utf-8"):
        self.send_bytes(text.encode("utf-8"), ctype, status=status)

    def send_html(self, html, status=200, extra=None):
        self.send_bytes(html.encode("utf-8"), "text/html; charset=utf-8", status=status, extra=extra)

    def error_json(self, message, status=400):
        self.send_json({"ok": False, "error": message}, status=status)

    def redirect(self, location, clear=False):
        self.send_response(303)
        self.send_header("Location", location)
        if clear:
            self.send_header("Set-Cookie", f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
        self.end_headers()


class PanelHandler(BaseHandler):
    def cookies(self):
        jar = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                jar[k] = v
        return jar

    def authed(self):
        token = self.cookies().get(COOKIE)
        return bool(token) and verify_token(token, STATE["config"]["secret"])

    def client(self):
        return self.address_string()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/login":
            if self.authed():
                return self.redirect("/")
            return self.send_html(render_login())
        if path == "/logout":
            log_activity("logout", "", self.client())
            return self.redirect("/login", clear=True)
        if path == "/favicon.ico":
            return self.send_bytes(FAVICON, "image/svg+xml")
        if not self.authed():
            return self.redirect("/login")
        if path == "/":
            return self.send_html(render_panel())
        fn = ROUTE_GET.get(path)
        if fn:
            try:
                return fn(self, parsed)
            except PermissionError:
                return self.error_json("forbidden", status=403)
            except Exception as e:
                eprint(f"  [error] GET {path}: {e}")
                return self.error_json(str(e), status=500)
        return self.send_text("Not found", status=404)

    def do_HEAD(self):
        return self.do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/login":
            return self.do_login()
        if not self.authed():
            return self.error_json("auth required", status=401)
        fn = ROUTE_POST.get(path)
        if fn:
            try:
                return fn(self, parsed)
            except PermissionError:
                return self.error_json("forbidden", status=403)
            except Exception as e:
                eprint(f"  [error] POST {path}: {e}")
                return self.error_json(str(e), status=500)
        return self.error_json("not found", status=404)

    def do_login(self):
        form = urllib.parse.parse_qs(self.read_body().decode("utf-8", "replace"))
        account = (form.get("account") or [""])[0]
        password = (form.get("password") or [""])[0]
        cfg = STATE["config"]
        if account == cfg["account"] and verify_password(password, cfg["password"]):
            token = make_token(cfg["secret"])
            log_activity("login", account, self.client())
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"{COOKIE}={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict")
            self.end_headers()
            return
        return self.send_html(render_login("Invalid account or password."), status=401)

    def qs(self, parsed):
        return urllib.parse.parse_qs(parsed.query)

    def target(self, rel):
        return safe_path(rel)


def _dir_listing(target, show_hidden):
    entries = []
    total = files = 0
    for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        if not show_hidden and is_internal(item.name):
            continue
        try:
            st = item.stat()
            is_dir = item.is_dir()
            size = 0 if is_dir else st.st_size
            entries.append({
                "name": item.name,
                "type": "dir" if is_dir else "file",
                "size": size,
                "size_h": "" if is_dir else human_size(size),
                "mtime": int(st.st_mtime),
                "mtime_h": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                "mode": oct(st.st_mode & 0o777)[2:].zfill(3),
                "ext": (item.suffix[1:].lower() if item.is_file() else ""),
            })
            if not is_dir:
                total += size
                files += 1
        except OSError:
            continue
    return entries, total, files


@route_get("/api/sysinfo")
def api_sysinfo(h, parsed):
    return h.send_json({"ok": True, "info": sysinfo(), "mem": meminfo(), "metrics": metrics(),
                        "activity": read_activity(8)})


@route_get("/api/metrics")
def api_metrics(h, parsed):
    return h.send_json({"ok": True, **metrics()})


@route_get("/api/list")
def api_list(h, parsed):
    qs = h.qs(parsed)
    rel = (qs.get("path") or [""])[0]
    show_hidden = (qs.get("hidden") or ["0"])[0] == "1"
    sort = (qs.get("sort") or ["name"])[0]
    direction = (qs.get("dir") or ["asc"])[0]
    target = h.target(rel)
    if not target.exists():
        return h.error_json("not found", status=404)
    if target.is_file():
        return h.error_json("not a directory", status=400)
    entries, total, files = _dir_listing(target, show_hidden)
    keymap = {
        "name": lambda e: e["name"].lower(),
        "size": lambda e: e["size"],
        "mtime": lambda e: e["mtime"],
        "type": lambda e: (e["type"], e["name"].lower()),
    }
    entries.sort(key=keymap.get(sort, keymap["name"]), reverse=(direction == "desc"))
    parent = rel_of(target.parent) if target != ROOT else None
    return h.send_json({
        "ok": True, "path": rel_of(target), "parent": parent, "entries": entries,
        "stats": {"files": files, "bytes": total, "bytes_h": human_size(total), "root": str(ROOT)},
    })


@route_get("/api/search")
def api_search(h, parsed):
    qs = h.qs(parsed)
    q = ((qs.get("q") or [""])[0]).strip().lower()
    if not q:
        return h.send_json({"ok": True, "results": []})
    results = []
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if not is_internal(d)]
        for name in names:
            if is_internal(name):
                continue
            if q in name.lower():
                p = Path(base) / name
                try:
                    st = p.stat()
                    results.append({"path": rel_of(p), "size_h": human_size(st.st_size),
                                    "mtime_h": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))})
                except OSError:
                    continue
                if len(results) >= 200:
                    return h.send_json({"ok": True, "results": results, "truncated": True})
    return h.send_json({"ok": True, "results": results})


@route_get("/api/stat")
def api_stat(h, parsed):
    qs = h.qs(parsed)
    target = h.target((qs.get("path") or [""])[0])
    if not target.exists():
        return h.error_json("not found", status=404)
    st = target.stat()
    children = len(list(target.iterdir())) if target.is_dir() else 0
    return h.send_json({"ok": True, "stat": {
        "name": target.name, "path": rel_of(target), "type": "dir" if target.is_dir() else "file",
        "size": st.st_size, "size_h": human_size(st.st_size), "mode": oct(st.st_mode & 0o777)[2:].zfill(3),
        "mtime": st.st_mtime, "mtime_h": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
        "children": children,
    }})


@route_get("/api/raw")
def api_raw(h, parsed):
    target = h.target((h.qs(parsed).get("path") or [""])[0])
    if not target.is_file():
        return h.error_json("not a file", status=404)
    data = target.read_bytes()
    if b"\x00" in data[:8192]:
        return h.send_json({"ok": True, "binary": True, "path": rel_of(target), "size": len(data)})
    return h.send_json({"ok": True, "binary": False, "path": rel_of(target),
                        "content": data.decode("utf-8", "replace")})


@route_get("/api/download")
def api_download(h, parsed):
    qs = h.qs(parsed)
    target = h.target((qs.get("path") or [""])[0])
    if not target.is_file():
        return h.error_json("not a file", status=404)
    inline = (qs.get("inline") or ["0"])[0] == "1"
    ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
    disp = "inline" if inline else "attachment"
    h.send_bytes(target.read_bytes(), ctype,
                 extra={"Content-Disposition": f'{disp}; filename="{target.name}"'})


@route_get("/api/zip")
def api_zip(h, parsed):
    target = h.target((h.qs(parsed).get("path") or [""])[0])
    if not target.exists():
        return h.error_json("not found", status=404)
    if target.is_file():
        buf = zip_paths([target], [target.name])
        name = target.name + ".zip"
    else:
        name = f"{target.name or 'root'}.zip"
        buf = zip_paths([target], [target.name or "root"])
    h.send_bytes(buf.read(), "application/zip",
                 extra={"Content-Disposition": f'attachment; filename="{name}"'})


@route_post("/api/upload")
def api_upload(h, parsed):
    ctype = h.headers.get("Content-Type") or ""
    if "boundary=" not in ctype:
        return h.error_json("expected multipart form")
    boundary = ctype.split("boundary=", 1)[1].strip().strip('"').encode()
    form, files = {}, []
    for name, filename, content in parse_multipart(h.read_body(), boundary):
        if filename:
            files.append((filename, content))
        elif name:
            form[name] = content.decode("utf-8", "replace")
    target = safe_path(form.get("path", ""))
    if not target.is_dir():
        return h.error_json("target is not a directory")
    saved = []
    for filename, content in files:
        safe_name = os.path.basename(filename.replace("\\", "/"))
        if not safe_name:
            continue
        dest = target / safe_name
        i = 1
        while dest.exists() and dest.is_dir():
            dest = target / f"{safe_name}.{i}"
            i += 1
        dest.write_bytes(content)
        saved.append(safe_name)
    log_activity("upload", f"{len(saved)} file(s) to {rel_of(target)}", h.client())
    return h.send_json({"ok": True, "saved": saved})


@route_post("/api/save")
def api_save(h, parsed):
    data = h.read_json()
    target = safe_path(data.get("path", ""))
    if target.is_dir():
        return h.error_json("cannot write to a directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data.get("content", ""), encoding="utf-8")
    log_activity("save", rel_of(target), h.client())
    return h.send_json({"ok": True, "path": rel_of(target), "size": target.stat().st_size})


@route_post("/api/mkdir")
def api_mkdir(h, parsed):
    data = h.read_json()
    name = os.path.basename((data.get("name") or "").replace("\\", "/"))
    if not name:
        return h.error_json("name required")
    target = safe_path(data.get("path", "")) / name
    if target.exists():
        return h.error_json("already exists")
    target.mkdir(parents=True)
    log_activity("mkdir", rel_of(target), h.client())
    return h.send_json({"ok": True, "path": rel_of(target)})


@route_post("/api/newfile")
def api_newfile(h, parsed):
    data = h.read_json()
    name = os.path.basename((data.get("name") or "").replace("\\", "/"))
    if not name:
        return h.error_json("name required")
    target = safe_path(data.get("path", "")) / name
    if target.exists():
        return h.error_json("already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("", encoding="utf-8")
    log_activity("newfile", rel_of(target), h.client())
    return h.send_json({"ok": True, "path": rel_of(target)})


@route_post("/api/rename")
def api_rename(h, parsed):
    data = h.read_json()
    src = safe_path(data.get("path", ""))
    newname = os.path.basename((data.get("newname") or "").replace("\\", "/"))
    if not newname:
        return h.error_json("new name required")
    if not src.exists():
        return h.error_json("not found", status=404)
    dest = src.parent / newname
    if dest.exists():
        return h.error_json("target already exists")
    src.rename(dest)
    log_activity("rename", f"{rel_of(src)} -> {rel_of(dest)}", h.client())
    return h.send_json({"ok": True, "path": rel_of(dest)})


@route_post("/api/delete")
def api_delete(h, parsed):
    target = safe_path(h.read_json().get("path", ""))
    if target == ROOT:
        return h.error_json("refusing to delete root", status=403)
    if not target.exists():
        return h.error_json("not found", status=404)
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    log_activity("delete", rel_of(target), h.client())
    return h.send_json({"ok": True})


def _transfer(h, data, move):
    src = safe_path(data.get("src", ""))
    dst = safe_path(data.get("dst", ""))
    if not src.exists():
        return h.error_json("source not found", status=404)
    if src == ROOT:
        return h.error_json("refusing to move root", status=403)
    if dst.is_dir():
        dst = dst / src.name
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        return h.error_json("destination already exists")
    if move:
        shutil.move(str(src), str(dst))
    elif src.is_dir():
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)
    log_activity("move" if move else "copy", f"{rel_of(src)} -> {rel_of(dst)}", h.client())
    return h.send_json({"ok": True, "path": rel_of(dst)})


@route_post("/api/copy")
def api_copy(h, parsed):
    return _transfer(h, h.read_json(), False)


@route_post("/api/move")
def api_move(h, parsed):
    return _transfer(h, h.read_json(), True)


@route_post("/api/unzip")
def api_unzip(h, parsed):
    target = safe_path(h.read_json().get("path", ""))
    if not target.is_file() or not zipfile.is_zipfile(target):
        return h.error_json("not a zip file")
    out = target.parent / target.stem
    i = 1
    while out.exists():
        out = target.parent / f"{target.stem}_{i}"
        i += 1
    out.mkdir()
    with zipfile.ZipFile(target) as zf:
        extract_zip(zf, out)
    log_activity("unzip", rel_of(target), h.client())
    return h.send_json({"ok": True, "path": rel_of(out)})


@route_post("/api/chmod")
def api_chmod(h, parsed):
    data = h.read_json()
    target = safe_path(data.get("path", ""))
    mode = str(data.get("mode", "")).strip()
    if not re.fullmatch(r"[0-7]{3,4}", mode):
        return h.error_json("mode must be octal like 755")
    try:
        os.chmod(target, int(mode, 8))
    except (OSError, NotImplementedError) as e:
        return h.error_json(f"chmod not supported here: {e}")
    log_activity("chmod", f"{rel_of(target)} {mode}", h.client())
    return h.send_json({"ok": True, "mode": oct(target.stat().st_mode & 0o777)[2:].zfill(3)})


@route_post("/api/bulk")
def api_bulk(h, parsed):
    data = h.read_json()
    action = data.get("action")
    paths = data.get("paths") or []
    targets = [safe_path(p) for p in paths]
    if not targets:
        return h.error_json("no paths")
    if action == "delete":
        for t in targets:
            if t == ROOT:
                continue
            if t.is_dir():
                shutil.rmtree(t)
            elif t.exists():
                t.unlink()
        log_activity("bulk delete", f"{len(targets)} item(s)", h.client())
        return h.send_json({"ok": True})
    if action in ("copy", "move"):
        dst = safe_path(data.get("dst", ""))
        if not dst.is_dir():
            return h.error_json("destination must be a directory")
        for t in targets:
            d = dst / t.name
            if d.exists():
                continue
            if action == "move":
                shutil.move(str(t), str(d))
            elif t.is_dir():
                shutil.copytree(t, d)
            else:
                shutil.copy2(t, d)
        log_activity(f"bulk {action}", f"{len(targets)} item(s)", h.client())
        return h.send_json({"ok": True})
    return h.error_json("unknown action")


@route_post("/api/bulk_download")
def api_bulk_download(h, parsed):
    data = h.read_json()
    targets = [safe_path(p) for p in (data.get("paths") or [])]
    targets = [t for t in targets if t.exists()]
    if not targets:
        return h.error_json("no paths")
    buf = zip_paths(targets, [t.name for t in targets])
    h.send_bytes(buf.read(), "application/zip",
                 extra={"Content-Disposition": 'attachment; filename="lpanel-selection.zip"'})


@route_post("/api/terminal")
def api_terminal(h, parsed):
    command = (h.read_json().get("command") or "").strip()
    if not command:
        return h.send_json({"ok": True, "output": "", "cwd": str(ROOT)})
    log_activity("terminal", command[:120], h.client())
    result = get_shell().run(command)
    return h.send_json({"ok": True, "output": result["output"], "cwd": result["cwd"]})


@route_post("/api/terminal/reset")
def api_terminal_reset(h, parsed):
    get_shell().start()
    return h.send_json({"ok": True})


def _db_dir():
    d = DATA_DIR / "databases"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _db_path(name):
    name = os.path.basename((name or "").replace("\\", "/"))
    if not name.endswith(".db"):
        name += ".db"
    if not re.fullmatch(r"[\w.\- ]+", name):
        raise ValueError("invalid database name")
    return _db_dir() / name


@route_get("/api/db/list")
def api_db_list(h, parsed):
    dbs = []
    for p in sorted(_db_dir().glob("*.db")):
        st = p.stat()
        tables = 0
        try:
            con = sqlite3.connect(str(p))
            tables = con.execute("select count(*) from sqlite_master where type='table'").fetchone()[0]
            con.close()
        except sqlite3.Error:
            pass
        dbs.append({"name": p.name, "size_h": human_size(st.st_size),
                    "mtime_h": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                    "tables": tables})
    return h.send_json({"ok": True, "databases": dbs})


@route_post("/api/db/create")
def api_db_create(h, parsed):
    name = (h.read_json().get("name") or "").strip()
    if not name:
        return h.error_json("name required")
    path = _db_path(name)
    if path.exists():
        return h.error_json("database already exists")
    con = sqlite3.connect(str(path))
    con.close()
    log_activity("db create", path.name, h.client())
    return h.send_json({"ok": True, "name": path.name})


@route_get("/api/db/tables")
def api_db_tables(h, parsed):
    path = _db_path((h.qs(parsed).get("db") or [""])[0])
    if not path.exists():
        return h.error_json("database not found", status=404)
    con = sqlite3.connect(str(path))
    try:
        rows = con.execute("select name from sqlite_master where type='table' order by name").fetchall()
    finally:
        con.close()
    return h.send_json({"ok": True, "tables": [r[0] for r in rows]})


@route_get("/api/db/data")
def api_db_data(h, parsed):
    qs = h.qs(parsed)
    path = _db_path((qs.get("db") or [""])[0])
    table = (qs.get("table") or [""])[0]
    limit = min(int((qs.get("limit") or ["100"])[0] or 100), 1000)
    offset = max(int((qs.get("offset") or ["0"])[0] or 0), 0)
    if not path.exists():
        return h.error_json("database not found", status=404)
    if not re.fullmatch(r"[\w ]+", table):
        return h.error_json("invalid table")
    con = sqlite3.connect(str(path))
    try:
        cur = con.execute(f'select * from "{table}" limit ? offset ?', (limit, offset))
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = [list(r) for r in cur.fetchall()]
        total = con.execute(f'select count(*) from "{table}"').fetchone()[0]
    finally:
        con.close()
    return h.send_json({"ok": True, "columns": cols, "rows": rows, "total": total})


@route_post("/api/db/query")
def api_db_query(h, parsed):
    data = h.read_json()
    path = _db_path(data.get("db", ""))
    sql = (data.get("sql") or "").strip()
    if not path.exists():
        return h.error_json("database not found", status=404)
    if not sql:
        return h.error_json("sql required")
    con = sqlite3.connect(str(path))
    try:
        cur = con.execute(sql)
        if cur.description:
            cols = [d[0] for d in cur.description]
            rows = [list(r) for r in cur.fetchmany(1000)]
            result = {"columns": cols, "rows": rows, "rowcount": len(rows), "kind": "select"}
        else:
            con.commit()
            result = {"columns": [], "rows": [], "rowcount": cur.rowcount, "kind": "write"}
    except sqlite3.Error as e:
        con.close()
        return h.error_json(f"SQL error: {e}")
    con.close()
    log_activity("db query", path.name, h.client())
    return h.send_json({"ok": True, **result})


@route_post("/api/db/drop")
def api_db_drop(h, parsed):
    path = _db_path(h.read_json().get("db", ""))
    if not path.exists():
        return h.error_json("database not found", status=404)
    path.unlink()
    log_activity("db drop", path.name, h.client())
    return h.send_json({"ok": True})


def _sched_file():
    return DATA_DIR / "scheduler.json"


def _load_jobs():
    return read_json_file(_sched_file(), [])


def _save_jobs(jobs):
    write_json_file(_sched_file(), jobs)


def run_job(job):
    try:
        r = subprocess.run(job["command"], shell=True, cwd=str(ROOT),
                           capture_output=True, text=True, timeout=int(job.get("timeout", 120)))
        out = (r.stdout or "") + (r.stderr or "")
        job["last_result"] = (f"exit {r.returncode}\n" + out)[:4000]
    except subprocess.TimeoutExpired:
        job["last_result"] = "timeout"
    except Exception as e:
        job["last_result"] = f"error: {e}"
    job["last_run"] = now()
    return job


def scheduler_loop():
    while True:
        try:
            jobs = _load_jobs()
            changed = False
            for job in jobs:
                if not job.get("enabled", True):
                    continue
                interval = max(int(job.get("interval", 60)), 10)
                last = job.get("last_run", 0)
                if now() - last >= interval:
                    run_job(job)
                    log_activity("schedule run", job.get("name", ""), "scheduler")
                    changed = True
            if changed:
                _save_jobs(jobs)
        except Exception as e:
            eprint(f"  [scheduler] {e}")
        time.sleep(5)


@route_get("/api/cron/list")
def api_cron_list(h, parsed):
    jobs = _load_jobs()
    for j in jobs:
        interval = max(int(j.get("interval", 60)), 10)
        j["next_run"] = max(0, interval - (now() - j.get("last_run", 0)))
    return h.send_json({"ok": True, "jobs": jobs})


@route_post("/api/cron/add")
def api_cron_add(h, parsed):
    data = h.read_json()
    name = (data.get("name") or "").strip()
    command = (data.get("command") or "").strip()
    if not command:
        return h.error_json("command required")
    interval = max(int(data.get("interval") or 60), 10)
    jobs = _load_jobs()
    job = {"id": secrets.token_hex(4), "name": name or command[:30], "command": command,
           "interval": interval, "enabled": True, "last_run": 0, "last_result": ""}
    jobs.append(job)
    _save_jobs(jobs)
    log_activity("schedule add", job["name"], h.client())
    return h.send_json({"ok": True, "job": job})


@route_post("/api/cron/delete")
def api_cron_delete(h, parsed):
    jid = h.read_json().get("id")
    jobs = [j for j in _load_jobs() if j.get("id") != jid]
    _save_jobs(jobs)
    log_activity("schedule delete", jid, h.client())
    return h.send_json({"ok": True})


@route_post("/api/cron/toggle")
def api_cron_toggle(h, parsed):
    jid = h.read_json().get("id")
    jobs = _load_jobs()
    for j in jobs:
        if j.get("id") == jid:
            j["enabled"] = not j.get("enabled", True)
    _save_jobs(jobs)
    return h.send_json({"ok": True})


@route_post("/api/cron/run")
def api_cron_run(h, parsed):
    jid = h.read_json().get("id")
    jobs = _load_jobs()
    result = None
    for j in jobs:
        if j.get("id") == jid:
            result = run_job(j)
    _save_jobs(jobs)
    log_activity("schedule run-now", jid, h.client())
    return h.send_json({"ok": True, "job": result})


def _protect_file():
    return DATA_DIR / "protect.json"


@route_get("/api/protect/list")
def api_protect_list(h, parsed):
    return h.send_json({"ok": True, "dirs": read_json_file(_protect_file(), {})})


@route_post("/api/protect/add")
def api_protect_add(h, parsed):
    data = h.read_json()
    rel = (data.get("path") or "").strip().strip("/")
    user = (data.get("user") or "").strip()
    password = data.get("password") or ""
    if not user or not password:
        return h.error_json("username and password required")
    full = (ROOT / PUBLIC_DIR / rel).resolve()
    pub = (ROOT / PUBLIC_DIR).resolve()
    if full != pub and pub not in full.parents:
        return h.error_json("path must be inside public_html")
    dirs = read_json_file(_protect_file(), {})
    dirs[rel] = {"user": user, "password": hash_password(password)}
    write_json_file(_protect_file(), dirs)
    log_activity("protect dir", rel, h.client())
    return h.send_json({"ok": True})


@route_post("/api/protect/remove")
def api_protect_remove(h, parsed):
    rel = (h.read_json().get("path") or "").strip().strip("/")
    dirs = read_json_file(_protect_file(), {})
    dirs.pop(rel, None)
    write_json_file(_protect_file(), dirs)
    log_activity("unprotect dir", rel, h.client())
    return h.send_json({"ok": True})


def _backup_dir():
    d = DATA_DIR / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


@route_get("/api/backup/list")
def api_backup_list(h, parsed):
    items = []
    for p in sorted(_backup_dir().glob("*.zip"), reverse=True):
        st = p.stat()
        items.append({"name": p.name, "size_h": human_size(st.st_size),
                      "mtime_h": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))})
    return h.send_json({"ok": True, "backups": items})


@route_post("/api/backup/create")
def api_backup_create(h, parsed):
    source = (h.read_json().get("source") or "root").strip()
    if source == "root":
        targets = [ROOT]
    elif source == "public":
        targets = [ROOT / PUBLIC_DIR]
    else:
        targets = [safe_path(source)]
    name = f"backup-{time.strftime('%Y%m%d-%H%M%S')}.zip"
    dest = _backup_dir() / name
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for t in targets:
            if t.is_dir():
                for item in t.rglob("*"):
                    if is_internal(item.parts[len(ROOT.parts)]) if len(item.parts) > len(ROOT.parts) else False:
                        continue
                    rel = item.relative_to(ROOT)
                    if item.name == DATA_NAME or item.name == CONFIG_NAME:
                        continue
                    if item.is_dir():
                        zf.writestr(str(rel).rstrip("/") + "/", "")
                    else:
                        try:
                            zf.write(item, str(rel))
                        except OSError:
                            pass
            else:
                zf.write(t, t.name)
    log_activity("backup create", name, h.client())
    return h.send_json({"ok": True, "name": name})


@route_get("/api/backup/download")
def api_backup_download(h, parsed):
    name = os.path.basename((h.qs(parsed).get("name") or [""])[0])
    path = _backup_dir() / name
    if not path.is_file():
        return h.error_json("not found", status=404)
    h.send_bytes(path.read_bytes(), "application/zip",
                 extra={"Content-Disposition": f'attachment; filename="{name}"'})


@route_post("/api/backup/delete")
def api_backup_delete(h, parsed):
    name = os.path.basename(h.read_json().get("name", ""))
    path = _backup_dir() / name
    if path.is_file():
        path.unlink()
    log_activity("backup delete", name, h.client())
    return h.send_json({"ok": True})


@route_get("/api/activity")
def api_activity(h, parsed):
    return h.send_json({"ok": True, "activity": read_activity(200)})


@route_get("/api/settings")
def api_settings(h, parsed):
    cfg = STATE["config"]
    site_dir = ROOT / PUBLIC_DIR
    du = None
    try:
        du = shutil.disk_usage(str(ROOT))
    except OSError:
        pass
    return h.send_json({"ok": True, "settings": {
        "account": cfg["account"], "panel_port": cfg["panel_port"], "site_port": cfg["site_port"],
        "root": str(ROOT), "site_dir": str(site_dir), "version": VERSION,
        "python": sys.version.split()[0],
    }})


@route_post("/api/settings/account")
def api_settings_account(h, parsed):
    data = h.read_json()
    account = (data.get("account") or "").strip()
    if not account:
        return h.error_json("account required")
    STATE["config"]["account"] = account
    save_config(STATE["config"])
    log_activity("settings account", account, h.client())
    return h.send_json({"ok": True, "account": account})


@route_post("/api/settings/password")
def api_settings_password(h, parsed):
    data = h.read_json()
    current = data.get("current") or ""
    new = data.get("new") or ""
    if not verify_password(current, STATE["config"]["password"]):
        return h.error_json("current password is incorrect", status=403)
    if len(new) < 4:
        return h.error_json("new password too short")
    STATE["config"]["password"] = hash_password(new)
    save_config(STATE["config"])
    log_activity("settings password", "changed", h.client())
    return h.send_json({"ok": True})


class SiteHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "lPanel-site"

    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, fmt, *args):
        eprint(f"  [site] {self.address_string()}  {fmt % args}")

    def _protected_for(self, path):
        dirs = read_json_file(_protect_file(), {})
        if not dirs:
            return None
        pub = (ROOT / PUBLIC_DIR).resolve()
        full = Path(path).resolve()
        if full != pub and pub not in full.parents:
            return None
        rel = full.relative_to(pub)
        parts = list(rel.parts)
        for i in range(len(parts), -1, -1):
            key = "/".join(parts[:i])
            if key in dirs:
                return dirs[key]
        return None

    def send_head(self):
        protected = self._protected_for(self.translate_path(self.path))
        if protected:
            auth = self.headers.get("Authorization") or ""
            ok = False
            if auth.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth[6:]).decode("utf-8", "replace")
                    user, _, pw = decoded.partition(":")
                    ok = user == protected["user"] and verify_password(pw, protected["password"])
                except Exception:
                    ok = False
            if not ok:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="lPanel protected area"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
        return super().send_head()


def start_server(port, handler, factory=False):
    if factory:
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    else:
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def start_panel(port):
    return start_server(port, PanelHandler)


def start_site(port, directory):
    def factory(*args, **kwargs):
        return SiteHandler(*args, directory=str(directory), **kwargs)
    return start_server(port, factory)


FAVICON = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
           b'<rect width="32" height="32" rx="8" fill="#ffd24a"/>'
           b'<text x="16" y="23" font-family="system-ui" font-size="20" font-weight="800" '
           b'text-anchor="middle" fill="#1a1600">l</text></svg>')


def render_login(error=""):
    err = f'<p class="err">{error}</p>' if error else ""
    return LOGIN_HTML.replace("__ERROR__", err).replace("__VERSION__", VERSION)


def render_panel():
    cfg = STATE["config"]
    return (PANEL_HTML
            .replace("__ACCOUNT__", cfg["account"])
            .replace("__SITE_PORT__", str(cfg["site_port"]))
            .replace("__PANEL_PORT__", str(cfg["panel_port"]))
            .replace("__ROOT__", str(ROOT))
            .replace("__VERSION__", VERSION))


def reset_password():
    cfg = load_config()
    print("Set a new password for account:", cfg["account"])
    while True:
        pw = ask_password()
        if pw:
            break
    cfg["password"] = hash_password(pw)
    save_config(cfg)
    print("Password updated.")


def parse_args(argv):
    opts = {"setup": False, "reset": False, "port": None, "no_browser": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--setup", "-s"):
            opts["setup"] = True
        elif a in ("--reset-password", "--reset"):
            opts["reset"] = True
        elif a == "--port":
            i += 1
            opts["port"] = int(argv[i])
        elif a == "--no-browser":
            opts["no_browser"] = True
        else:
            print(f"Unknown option: {a}")
            sys.exit(2)
        i += 1
    return opts


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass
    opts = parse_args(sys.argv[1:])
    if opts["reset"]:
        return reset_password()

    if opts["setup"] or not CONFIG_PATH.exists():
        config = setup_wizard(load_config() if CONFIG_PATH.exists() and opts["setup"] else None)
        save_config(config)
        print(f"\n  Config saved to {CONFIG_PATH}")
    else:
        config = load_config()

    if opts["port"]:
        config["panel_port"] = opts["port"]
    STATE["config"] = config
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass

    ensure_dirs()
    public = ROOT / PUBLIC_DIR
    threading.Thread(target=scheduler_loop, daemon=True).start()

    try:
        panel = start_panel(config["panel_port"])
    except OSError as e:
        eprint(f"Could not bind panel port {config['panel_port']}: {e}")
        sys.exit(1)
    try:
        site = start_site(config["site_port"], public)
    except OSError as e:
        eprint(f"Could not bind site port {config['site_port']}: {e}")
        panel.shutdown()
        sys.exit(1)

    panel_url = f"http://127.0.0.1:{config['panel_port']}"
    print()
    print("=" * 52)
    print(f"  lPanel {VERSION} is running")
    print("=" * 52)
    print(f"  Panel:    {panel_url}   (account: {config['account']})")
    print(f"  Site:     http://127.0.0.1:{config['site_port']}")
    print(f"  Root:     {ROOT}")
    print(f"  Website:  {public}")
    print("  Ctrl+C to stop")
    print()
    log_activity("panel start", f"v{VERSION}", "system")

    if not opts["no_browser"]:
        threading.Timer(0.7, lambda: webbrowser.open(panel_url)).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down lPanel.")
        if STATE.get("shell"):
            STATE["shell"].stop()
        panel.shutdown()
        site.shutdown()


LOGIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lPanel - Sign in</title>
<style>
  :root { color-scheme: dark; --accent:#ffd24a; --line:#26262b; --muted:#9a9aa5; }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: radial-gradient(900px 500px at 15% -10%, #2a2410 0%, transparent 60%), radial-gradient(700px 500px at 100% 110%, #14201a 0%, transparent 55%), #0e0e10;
    color:#ececf1; padding:20px; }
  .card { width:380px; max-width:100%; padding:34px; border-radius:18px; background:#161619; border:1px solid var(--line);
    box-shadow: 0 30px 80px rgba(0,0,0,.55); }
  .brand { display:flex; align-items:center; gap:12px; }
  .logo { width:38px; height:38px; border-radius:11px; background:var(--accent); color:#1a1600; display:grid; place-items:center; font-weight:800; font-size:20px; }
  h1 { font-size:19px; margin:0; letter-spacing:.2px; }
  .brand .v { color:var(--muted); font-size:11px; }
  p.sub { color:var(--muted); font-size:13px; margin:16px 0 8px; }
  label { display:block; font-size:12px; color:var(--muted); margin:16px 0 6px; }
  input { width:100%; padding:12px 13px; border-radius:11px; border:1px solid #2f2f37; background:#0f0f12; color:#ececf1; font-size:14px; transition:.15s; }
  input:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(255,210,74,.15); }
  button { width:100%; margin-top:24px; padding:13px; border:0; border-radius:11px; background:var(--accent); color:#1a1600; font-weight:700; font-size:14px; cursor:pointer; transition:.15s; }
  button:hover { background:#ffdd73; }
  .err { color:#ff9b9b; font-size:13px; margin:14px 0 0; background:#2a1618; border:1px solid #4a2327; padding:9px 12px; border-radius:9px; }
  .foot { text-align:center; color:#5c5c66; font-size:11px; margin-top:22px; }
</style>
</head>
<body>
  <form class="card" method="post" action="/login">
    <div class="brand"><div class="logo">l</div><div><h1>lPanel</h1><div class="v">v__VERSION__</div></div></div>
    <p class="sub">Sign in to your hosting panel</p>
    __ERROR__
    <label>Account</label>
    <input name="account" autocomplete="username" autofocus>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
    <div class="foot">secured session · localhost only</div>
  </form>
</body>
</html>"""


PANEL_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lPanel</title>
<style>
  :root {
    color-scheme: dark;
    --bg:#0e0e10; --bg2:#131316; --panel:#17171a; --elev:#1c1c20; --line:#26262b; --line2:#303039;
    --text:#ececf1; --muted:#9a9aa5; --dim:#6c6c78;
    --accent:#ffd24a; --accent-ink:#1a1600; --green:#63d19b; --blue:#6ba8ff; --red:#ff6b6b; --purple:#b48bff;
    --radius:12px; --radius-lg:16px; --shadow:0 18px 50px rgba(0,0,0,.45);
  }
  * { box-sizing:border-box; }
  html,body { height:100%; }
  body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  a { color:inherit; }
  button { font:inherit; }
  ::-webkit-scrollbar { width:10px; height:10px; }
  ::-webkit-scrollbar-thumb { background:#2c2c33; border-radius:8px; border:2px solid var(--bg); }
  ::-webkit-scrollbar-thumb:hover { background:#3a3a44; }
  :focus-visible { outline:2px solid var(--accent); outline-offset:2px; }

  .app { display:grid; grid-template-columns:248px 1fr; min-height:100vh; }

  .sidebar { background:var(--bg2); border-right:1px solid var(--line); padding:16px 12px; display:flex; flex-direction:column;
    position:sticky; top:0; height:100vh; }
  .brand { display:flex; align-items:center; gap:11px; padding:6px 8px 16px; }
  .logo { width:34px; height:34px; border-radius:10px; background:var(--accent); color:var(--accent-ink); display:grid; place-items:center; font-weight:800; font-size:19px; }
  .brand b { font-size:16px; letter-spacing:.2px; }
  .brand .v { color:var(--dim); font-size:10px; }
  .nav { display:flex; flex-direction:column; gap:2px; overflow:auto; flex:1; }
  .nav .grp { font-size:10px; text-transform:uppercase; letter-spacing:.8px; color:var(--dim); padding:14px 10px 6px; }
  .nav a { display:flex; align-items:center; gap:10px; padding:9px 11px; border-radius:9px; color:#cdcdd6; text-decoration:none;
    cursor:pointer; font-size:13.5px; transition:.12s; }
  .nav a:hover { background:var(--elev); color:#fff; }
  .nav a.active { background:rgba(255,210,74,.13); color:var(--accent); }
  .nav a .ic { width:17px; height:17px; opacity:.9; flex:none; }
  .side-foot { border-top:1px solid var(--line); padding:12px 10px 2px; color:var(--dim); font-size:11px; }
  .side-foot .path { color:var(--muted); word-break:break-all; }

  .topbar { display:flex; align-items:center; gap:14px; padding:12px 20px; border-bottom:1px solid var(--line);
    background:rgba(19,19,22,.85); backdrop-filter:blur(8px); position:sticky; top:0; z-index:30; }
  .topbar h2 { font-size:16px; margin:0; font-weight:650; }
  .menu-btn { display:none; }
  .grow { flex:1; }
  .pills { display:flex; gap:10px; }
  .pill { display:flex; align-items:center; gap:8px; background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:6px 11px; font-size:12px; }
  .pill .dot { width:7px; height:7px; border-radius:50%; background:var(--green); }
  .pill b { font-variant-numeric:tabular-nums; }
  .account { display:flex; align-items:center; gap:9px; padding:5px 6px 5px 12px; border:1px solid var(--line); border-radius:10px; background:var(--panel); }
  .avatar { width:26px; height:26px; border-radius:8px; background:linear-gradient(135deg,var(--accent),#ffb347); color:var(--accent-ink);
    display:grid; place-items:center; font-weight:800; font-size:13px; }

  .content { padding:22px 24px 60px; max-width:1240px; }
  .view { display:none; animation:fade .18s ease; }
  .view.active { display:block; }
  @keyframes fade { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:none; } }

  .btn { display:inline-flex; align-items:center; gap:7px; border:1px solid var(--line2); background:#1e1e22; color:var(--text);
    padding:8px 13px; border-radius:10px; cursor:pointer; font-size:13px; transition:.13s; text-decoration:none; white-space:nowrap; }
  .btn:hover { background:#26262c; border-color:#3a3a45; }
  .btn .ic { width:15px; height:15px; }
  .btn.primary { background:var(--accent); color:var(--accent-ink); border-color:var(--accent); font-weight:650; }
  .btn.primary:hover { background:#ffdd73; }
  .btn.ghost { background:transparent; border-color:transparent; }
  .btn.ghost:hover { background:var(--elev); }
  .btn.danger { color:#ff9d9d; }
  .btn.danger:hover { border-color:#7a2b2b; background:#2a1717; }
  .btn.sm { padding:5px 9px; font-size:12px; border-radius:8px; }
  .btn:disabled { opacity:.5; cursor:not-allowed; }
  .icon-btn { display:inline-grid; place-items:center; width:34px; height:34px; border-radius:9px; border:1px solid var(--line2);
    background:#1e1e22; color:var(--text); cursor:pointer; }
  .icon-btn:hover { background:#26262c; }
  .icon-btn .ic { width:17px; height:17px; }

  .toolbar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:14px; }
  .toolbar .grow { flex:1; }
  .field { display:flex; flex-direction:column; gap:5px; }
  .field label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }
  input[type=text], input[type=password], input[type=number], select, textarea {
    background:#0f0f12; border:1px solid #2f2f37; color:var(--text); border-radius:10px; padding:9px 11px; font-size:13px; transition:.13s; }
  input:focus, select:focus, textarea:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(255,210,74,.13); }
  .search { position:relative; }
  .search input { padding-left:34px; width:100%; }
  .search .ic { position:absolute; left:10px; top:50%; transform:translateY(-50%); width:15px; height:15px; color:var(--dim); }

  .crumbs { display:flex; flex-wrap:wrap; align-items:center; gap:4px; font-size:13px; margin-bottom:12px;
    padding:9px 12px; border:1px solid var(--line); border-radius:11px; background:var(--panel); }
  .crumbs a { color:var(--accent); text-decoration:none; cursor:pointer; }
  .crumbs a:hover { text-decoration:underline; }
  .crumbs .sep { color:#48484f; }

  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:var(--radius); overflow:hidden; }
  th, td { text-align:left; padding:10px 13px; border-bottom:1px solid var(--line); font-size:13px; vertical-align:middle; }
  th { background:#141416; color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.5px; cursor:pointer; user-select:none; }
  th.no-sort { cursor:default; }
  th .sort-ind { color:var(--accent); margin-left:4px; }
  tr:last-child td { border-bottom:0; }
  tbody tr:hover td { background:#1b1b20; }
  td.name { cursor:pointer; display:flex; align-items:center; gap:10px; }
  td.name .ficon { width:18px; height:18px; flex:none; }
  .badge { display:inline-block; font-size:10px; padding:2px 7px; border-radius:6px; font-weight:600; letter-spacing:.3px; }
  .badge.dir { background:rgba(255,210,74,.15); color:var(--accent); }
  .badge.file { background:rgba(107,168,255,.14); color:var(--blue); }
  td.actions { text-align:right; white-space:nowrap; }
  .rowactions { opacity:0; transition:.12s; }
  tr:hover .rowactions, tr:focus-within .rowactions { opacity:1; }
  .chk { width:16px; height:16px; accent-color:var(--accent); }

  .drop { border:2px dashed #34343d; border-radius:var(--radius); padding:18px; text-align:center; color:var(--muted);
    margin-top:14px; font-size:13px; transition:.15s; }
  .drop.hot { border-color:var(--accent); color:var(--accent); background:rgba(255,210,74,.06); }

  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:14px; }
  .kpi { background:var(--panel); border:1px solid var(--line); border-radius:var(--radius-lg); padding:16px 18px; position:relative; overflow:hidden; }
  .kpi .l { color:var(--muted); font-size:12px; display:flex; align-items:center; gap:7px; }
  .kpi .n { font-size:28px; font-weight:700; margin-top:8px; letter-spacing:-.5px; }
  .kpi .sub { color:var(--dim); font-size:12px; margin-top:2px; }
  .kpi .ic { width:16px; height:16px; }
  .bar { height:7px; border-radius:6px; background:#232329; overflow:hidden; margin-top:12px; }
  .bar > i { display:block; height:100%; border-radius:6px; background:var(--accent); transition:width .4s ease; }
  .bar.green > i { background:var(--green); }
  .bar.red > i { background:var(--red); }
  .bar.blue > i { background:var(--blue); }

  .card { background:var(--panel); border:1px solid var(--line); border-radius:var(--radius-lg); padding:18px; }
  .card h3 { margin:0 0 12px; font-size:14px; font-weight:650; }
  .grid2 { display:grid; grid-template-columns:1.4fr 1fr; gap:16px; }
  .muted { color:var(--muted); }
  .dim { color:var(--dim); }
  code, .mono { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
  .chip { display:inline-flex; align-items:center; gap:6px; padding:3px 9px; border-radius:20px; font-size:12px; border:1px solid var(--line2); background:var(--elev); }

  .feed { display:flex; flex-direction:column; gap:2px; }
  .feed .item { display:flex; gap:10px; padding:9px 4px; border-bottom:1px solid var(--line); font-size:13px; }
  .feed .item:last-child { border-bottom:0; }
  .feed .act { font-weight:600; }
  .feed .when { color:var(--dim); font-size:12px; white-space:nowrap; margin-left:auto; }

  .empty { text-align:center; color:var(--muted); padding:46px 20px; }
  .empty .ic { width:40px; height:40px; color:#3a3a44; }

  .overlay { position:fixed; inset:0; background:rgba(0,0,0,.55); backdrop-filter:blur(2px); display:none; z-index:60; }
  .overlay.show { display:block; }
  .modal { position:fixed; z-index:70; inset:0; display:none; align-items:center; justify-content:center; padding:22px; }
  .modal.show { display:flex; }
  .modal .box { width:min(560px,100%); background:var(--bg2); border:1px solid var(--line2); border-radius:var(--radius-lg);
    box-shadow:var(--shadow); max-height:90vh; display:flex; flex-direction:column; }
  .modal .box.wide { width:min(920px,100%); }
  .modal .head { display:flex; align-items:center; gap:10px; padding:15px 18px; border-bottom:1px solid var(--line); }
  .modal .head h3 { margin:0; font-size:15px; }
  .modal .body { padding:18px; overflow:auto; }
  .modal .foot { padding:14px 18px; border-top:1px solid var(--line); display:flex; justify-content:flex-end; gap:8px; }

  .editor-wrap { border:1px solid var(--line); border-radius:var(--radius); overflow:hidden; background:#101013; display:flex; }
  .gutter { padding:14px 10px; text-align:right; color:#4a4a55; font-family:ui-monospace, Menlo, monospace; font-size:13px; line-height:1.55;
    background:#131316; border-right:1px solid var(--line); user-select:none; min-width:48px; overflow:hidden; }
  .editor-wrap textarea { flex:1; border:0; background:#101013; color:var(--text); padding:14px; resize:none;
    font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px; line-height:1.55; outline:none; height:calc(100vh - 260px); min-height:320px; }
  .statusbar { display:flex; gap:16px; color:var(--dim); font-size:12px; padding:8px 4px; }

  .term { background:#0b0b0d; border:1px solid var(--line); border-radius:var(--radius); height:calc(100vh - 250px); min-height:340px;
    overflow:auto; padding:14px; font-family:ui-monospace, Menlo, monospace; font-size:13px; line-height:1.5; white-space:pre-wrap; word-break:break-word; }
  .term .cmd { color:var(--accent); }
  .term .err { color:#ff9d9d; }
  .term-in { display:flex; align-items:center; gap:9px; margin-top:10px; }
  .term-in .ps1 { color:var(--green); font-family:ui-monospace, Menlo, monospace; }
  .term-in input { flex:1; font-family:ui-monospace, Menlo, monospace; }

  .tabs { display:flex; gap:4px; border-bottom:1px solid var(--line); margin-bottom:16px; flex-wrap:wrap; }
  .tabs a { padding:9px 14px; cursor:pointer; font-size:13px; color:var(--muted); border-bottom:2px solid transparent; }
  .tabs a.active { color:var(--accent); border-bottom-color:var(--accent); }

  #toasts { position:fixed; right:20px; bottom:20px; display:flex; flex-direction:column; gap:9px; z-index:90; }
  .toast { background:var(--elev); border:1px solid var(--line2); border-left:3px solid var(--accent); padding:11px 15px;
    border-radius:11px; font-size:13px; box-shadow:var(--shadow); max-width:340px; animation:fade .18s ease; }
  .toast.ok { border-left-color:var(--green); }
  .toast.err { border-left-color:var(--red); }

  .skel { color:var(--dim); padding:30px; text-align:center; }
  .spin { width:18px; height:18px; border:2px solid #33333d; border-top-color:var(--accent); border-radius:50%; display:inline-block; animation:sp .7s linear infinite; }
  @keyframes sp { to { transform:rotate(360deg); } }

  @media (max-width:980px) {
    .app { grid-template-columns:1fr; }
    .sidebar { position:fixed; left:0; top:0; width:260px; z-index:80; transform:translateX(-100%); transition:.2s; box-shadow:var(--shadow); }
    .sidebar.open { transform:none; }
    .menu-btn { display:inline-grid; }
    .grid2 { grid-template-columns:1fr; }
    .content { padding:16px 14px 60px; }
    .pills .hide-sm { display:none; }
  }
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar" id="sidebar">
    <div class="brand"><div class="logo">l</div><div><b>lPanel</b><div class="v">v__VERSION__</div></div></div>
    <nav class="nav" id="nav">
      <div class="grp">Overview</div>
      <a data-view="dashboard">__I_dashboard__Dashboard</a>
      <a data-view="files">__I_folder__File Manager</a>
      <a data-view="editor">__I_code__Code Editor</a>
      <div class="grp">Tools</div>
      <a data-view="terminal">__I_terminal__Terminal</a>
      <a data-view="databases">__I_database__Databases</a>
      <a data-view="scheduler">__I_clock__Scheduled Tasks</a>
      <div class="grp">Security</div>
      <a data-view="security">__I_shield__Directory Protection</a>
      <a data-view="backups">__I_archive__Backups</a>
      <div class="grp">System</div>
      <a data-view="activity">__I_activity__Activity Log</a>
      <a data-view="settings">__I_settings__Settings</a>
    </nav>
    <div class="side-foot">
      <div>Root directory</div>
      <div class="path">__ROOT__</div>
    </div>
  </aside>

  <div>
    <div class="topbar">
      <button class="icon-btn menu-btn" id="menuBtn">__I_menu__</button>
      <h2 id="pageTitle">Dashboard</h2>
      <div class="grow"></div>
      <div class="pills">
        <span class="pill hide-sm"><span class="dot"></span>CPU <b id="mCpu">-</b></span>
        <span class="pill"><span class="dot" style="background:var(--blue)"></span>RAM <b id="mMem">-</b></span>
      </div>
      <a class="btn" id="viewSite" target="_blank" rel="noopener" href="#">__I_external__<span class="hide-sm">View Site</span></a>
      <div class="account"><span class="avatar" id="avatar">A</span><span class="hide-sm">__ACCOUNT__</span></div>
    </div>

    <main class="content">
      <section class="view active" id="view-dashboard">
        <div class="cards">
          <div class="kpi"><div class="l">__I_cpu__CPU usage</div><div class="n" id="kCpu">-</div>
            <div class="bar"><i id="kCpuBar" style="width:0"></i></div><div class="sub" id="kLoad">load -</div></div>
          <div class="kpi"><div class="l">__I_mem__Memory</div><div class="n" id="kMem">-</div>
            <div class="bar blue"><i id="kMemBar" style="width:0"></i></div><div class="sub" id="kMemSub">-</div></div>
          <div class="kpi"><div class="l">__I_disk__Disk</div><div class="n" id="kDisk">-</div>
            <div class="bar green"><i id="kDiskBar" style="width:0"></i></div><div class="sub" id="kDiskSub">-</div></div>
          <div class="kpi"><div class="l">__I_clock__Uptime</div><div class="n" id="kUptime">-</div>
            <div class="sub" id="kPy">-</div></div>
        </div>
        <div class="grid2" style="margin-top:16px">
          <div class="card">
            <h3>Quick actions</h3>
            <div class="toolbar">
              <button class="btn primary" data-goto="files">__I_folder__Open File Manager</button>
              <button class="btn" data-goto="terminal">__I_terminal__Open Terminal</button>
              <button class="btn" id="qaBackup">__I_archive__Create backup</button>
              <a class="btn" id="qaSite" target="_blank" rel="noopener" href="#">__I_external__Visit website</a>
            </div>
          </div>
          <div class="card">
            <h3>Recent activity</h3>
            <div class="feed" id="dashFeed"><div class="skel"><span class="spin"></span></div></div>
          </div>
        </div>
      </section>

      <section class="view" id="view-files">
        <div class="toolbar">
          <button class="btn primary" id="fUpload">__I_upload__Upload</button>
          <button class="btn" id="fNewFolder">__I_plus__Folder</button>
          <button class="btn" id="fNewFile">__I_plus__File</button>
          <button class="btn" id="fZip">__I_download__Zip folder</button>
          <div class="grow"></div>
          <label class="chip"><input type="checkbox" class="chk" id="fHidden"> hidden</label>
          <div class="search" style="width:230px">__I_search__<input type="text" id="fSearch" placeholder="Search all files..."></div>
          <button class="btn" id="fRefresh">__I_refresh__</button>
          <input type="file" id="fPicker" multiple hidden>
        </div>
        <div class="crumbs" id="fCrumbs"></div>
        <div id="fBulk" class="toolbar" style="display:none">
          <span class="chip"><b id="fBulkCount">0</b> selected</span>
          <button class="btn sm" id="bDown">__I_download__Download</button>
          <button class="btn sm" id="bCopy">Copy</button>
          <button class="btn sm" id="bMove">Move</button>
          <button class="btn sm danger" id="bDel">__I_trash__Delete</button>
        </div>
        <table>
          <thead><tr>
            <th class="no-sort" style="width:34px"><input type="checkbox" class="chk" id="fAll"></th>
            <th data-sort="name">Name</th>
            <th data-sort="size" style="width:110px">Size</th>
            <th data-sort="mtime" style="width:160px">Modified</th>
            <th class="no-sort" style="width:120px">Mode</th>
            <th class="no-sort" style="width:230px"></th>
          </tr></thead>
          <tbody id="fRows"></tbody>
        </table>
        <div class="drop" id="fDrop">Drag files here to upload to the current folder</div>
      </section>

      <section class="view" id="view-editor">
        <div class="toolbar">
          <span class="chip mono" id="edPath">no file open</span>
          <div class="grow"></div>
          <button class="btn" id="edOpen">__I_folder__Open file</button>
          <button class="btn" id="edDownload">__I_download__Download</button>
          <button class="btn primary" id="edSave">__I_save__Save</button>
        </div>
        <div class="editor-wrap">
          <div class="gutter" id="edGutter">1</div>
          <textarea id="edText" spellcheck="false" placeholder="Open a file from File Manager to edit it here..."></textarea>
        </div>
        <div class="statusbar"><span id="edStat">0 lines · 0 chars</span><span class="grow"></span><span>Ctrl+S to save</span></div>
      </section>

      <section class="view" id="view-terminal">
        <div class="toolbar">
          <span class="chip">__I_terminal__shell · <span class="mono" id="termCwd">__ROOT__</span></span>
          <div class="grow"></div>
          <button class="btn" id="termClear">Clear</button>
          <button class="btn" id="termReset">__I_refresh__Restart</button>
        </div>
        <div class="term" id="term"></div>
        <form class="term-in" id="termForm">
          <span class="ps1" id="termPs1">$</span>
          <input type="text" id="termCmd" autocomplete="off" spellcheck="false" placeholder="type a command and press Enter">
        </form>
      </section>

      <section class="view" id="view-databases">
        <div class="toolbar">
          <button class="btn primary" id="dbNew">__I_plus__New database</button>
          <button class="btn" id="dbRefresh">__I_refresh__</button>
        </div>
        <div class="grid2">
          <div class="card">
            <h3>Databases</h3>
            <div id="dbList"><div class="skel"><span class="spin"></span></div></div>
          </div>
          <div class="card">
            <h3 id="dbTitle">SQL console</h3>
            <div class="field"><label>SQL</label>
              <textarea id="dbSql" class="mono" style="min-height:110px" placeholder="SELECT * FROM sqlite_master;"></textarea></div>
            <div class="toolbar" style="margin:12px 0 0">
              <button class="btn primary" id="dbRun">Run query</button>
              <span class="dim" id="dbMsg"></span>
            </div>
            <div id="dbResult" style="margin-top:14px"></div>
          </div>
        </div>
      </section>

      <section class="view" id="view-scheduler">
        <div class="card" style="margin-bottom:16px">
          <h3>Add scheduled task</h3>
          <div class="toolbar">
            <div class="field"><label>Name</label><input type="text" id="scName" placeholder="nightly job"></div>
            <div class="field" style="flex:1;min-width:220px"><label>Command</label><input type="text" id="scCmd" placeholder="python3 tasks/cleanup.py"></div>
            <div class="field"><label>Every (sec)</label><input type="number" id="scInterval" value="3600" min="10" style="width:120px"></div>
            <button class="btn primary" id="scAdd" style="align-self:flex-end">__I_plus__Add</button>
          </div>
        </div>
        <table><thead><tr>
          <th class="no-sort">Name</th><th class="no-sort">Command</th><th class="no-sort" style="width:100px">Every</th>
          <th class="no-sort" style="width:120px">Next</th><th class="no-sort" style="width:90px">Status</th>
          <th class="no-sort" style="width:260px"></th>
        </tr></thead><tbody id="scRows"></tbody></table>
      </section>

      <section class="view" id="view-security">
        <div class="card" style="margin-bottom:16px">
          <h3>Password-protect a directory</h3>
          <p class="muted" style="margin-top:-4px">Visitors must enter credentials to view this folder on the website.</p>
          <div class="toolbar">
            <div class="field"><label>Folder in public_html</label><input type="text" id="secPath" placeholder="private"></div>
            <div class="field"><label>Username</label><input type="text" id="secUser" placeholder="guest"></div>
            <div class="field"><label>Password</label><input type="password" id="secPass" placeholder="secret"></div>
            <button class="btn primary" id="secAdd" style="align-self:flex-end">__I_lock__Protect</button>
          </div>
        </div>
        <table><thead><tr><th class="no-sort">Directory</th><th class="no-sort">Username</th><th class="no-sort" style="width:120px"></th></tr></thead>
        <tbody id="secRows"></tbody></table>
      </section>

      <section class="view" id="view-backups">
        <div class="toolbar">
          <select id="bkSource" style="width:220px">
            <option value="root">Whole directory</option>
            <option value="public">public_html only</option>
          </select>
          <button class="btn primary" id="bkCreate">__I_archive__Create backup</button>
          <div class="grow"></div>
          <button class="btn" id="bkRefresh">__I_refresh__</button>
        </div>
        <table><thead><tr><th class="no-sort">Backup</th><th class="no-sort" style="width:120px">Size</th>
          <th class="no-sort" style="width:170px">Created</th><th class="no-sort" style="width:190px"></th></tr></thead>
        <tbody id="bkRows"></tbody></table>
      </section>

      <section class="view" id="view-activity">
        <div class="toolbar"><div class="grow"></div><button class="btn" id="actRefresh">__I_refresh__Refresh</button></div>
        <div class="card"><div class="feed" id="actFeed"><div class="skel"><span class="spin"></span></div></div></div>
      </section>

      <section class="view" id="view-settings">
        <div class="grid2">
          <div class="card">
            <h3>Account</h3>
            <div class="field" style="margin-bottom:12px"><label>Account name</label><input type="text" id="stAccount"></div>
            <button class="btn primary" id="stSaveAccount">Save account</button>
          </div>
          <div class="card">
            <h3>Change password</h3>
            <div class="field" style="margin-bottom:12px"><label>Current password</label><input type="password" id="stCur"></div>
            <div class="field" style="margin-bottom:12px"><label>New password</label><input type="password" id="stNew"></div>
            <button class="btn primary" id="stSavePass">Update password</button>
          </div>
        </div>
        <div class="card" style="margin-top:16px">
          <h3>Server</h3>
          <div id="stInfo" class="muted"></div>
        </div>
      </section>
    </main>
  </div>
</div>

<div class="overlay" id="overlay"></div>
<div class="modal" id="modal"><div class="box" id="modalBox"></div></div>
<div id="toasts"></div>

<script>
const ACCOUNT = "__ACCOUNT__";
const SITE_URL = "http://127.0.0.1:__SITE_PORT__/";
const ROOT = "__ROOT__";

const ICONS = {
  dashboard:'<path d="M3 3h8v8H3zM13 3h8v5h-8zM13 12h8v9h-8zM3 15h8v6H3z"/>',
  folder:'<path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  file:'<path d="M14 3v5h5"/><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>',
  code:'<path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 4l-4 16"/>',
  terminal:'<path d="m4 6 5 5-5 5M13 17h7"/>',
  database:'<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  shield:'<path d="M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6z"/>',
  archive:'<rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8M10 12h4"/>',
  activity:'<path d="M3 12h4l2-6 4 12 2-6h6"/>',
  settings:'<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.3 1a7 7 0 0 0-1.7-1L14.5 3h-4l-.4 2.6a7 7 0 0 0-1.7 1l-2.3-1-2 3.4L6 11a7 7 0 0 0 0 2l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 1.7 1l.4 2.6h4l.4-2.6a7 7 0 0 0 1.7-1l2.3 1 2-3.4-2-1.5c.1-.3.1-.7.1-1z"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  upload:'<path d="M12 16V4M7 9l5-5 5 5M4 20h16"/>',
  download:'<path d="M12 4v12M7 11l5 5 5-5M4 20h16"/>',
  trash:'<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  edit:'<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  refresh:'<path d="M20 11a8 8 0 1 0-2 5.5"/><path d="M20 4v7h-7"/>',
  save:'<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8M7 3v5h8"/>',
  external:'<path d="M14 4h6v6M20 4l-9 9M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"/>',
  menu:'<path d="M4 7h16M4 12h16M4 17h16"/>',
  cpu:'<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>',
  mem:'<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 17v3M12 17v3M17 17v3M7 11h.01M12 11h.01M17 11h.01"/>',
  disk:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="2"/><path d="M12 3v3M19.8 7.5l-2.6 1.5M19.8 16.5l-2.6-1.5M12 21v-3M4.2 16.5l2.6-1.5M4.2 7.5l2.6 1.5"/>',
  lock:'<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  play:'<path d="M6 4l14 8-14 8z"/>',
  x:'<path d="M6 6l12 12M18 6 6 18"/>',
  home:'<path d="M4 11l8-7 8 7M6 10v10h12V10"/>',
  image:'<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9.5" r="1.5"/><path d="m4 17 5-5 4 4 3-3 4 4"/>',
  check:'<path d="M4 12l5 5L20 6"/>'
};
function svg(name, cls){
  const p = ICONS[name] || ICONS.file;
  return `<svg class="ic ${cls||''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
}
function hydrateIcons(root){
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = []; let n;
  while(n = walker.nextNode()){ if(n.nodeValue && n.nodeValue.includes('__I_')) nodes.push(n); }
  nodes.forEach(node=>{
    const span = document.createElement('span');
    span.style.display = 'inline-flex';
    span.style.alignItems = 'center';
    span.style.gap = '7px';
    span.innerHTML = node.nodeValue.replace(/__I_(\w+)__/g, (m,k)=>svg(k));
    node.parentNode.replaceChild(span, node);
  });
}

const $ = (s,el=document)=>el.querySelector(s);
const $$ = (s,el=document)=>[...el.querySelectorAll(s)];
const el = (tag, attrs={}, html)=>{ const e=document.createElement(tag); for(const k in attrs){ if(k==='class')e.className=attrs[k]; else e.setAttribute(k,attrs[k]); } if(html!=null)e.innerHTML=html; return e; };
const esc = s => String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtBytes = n => { n=Number(n); const u=['B','KB','MB','GB','TB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return (i===0?n.toFixed(0):n.toFixed(1))+' '+u[i]; };
const ago = t => { const d=Math.max(0,Math.floor(Date.now()/1000)-t); if(d<60)return d+'s ago'; if(d<3600)return Math.floor(d/60)+'m ago'; if(d<86400)return Math.floor(d/3600)+'h ago'; return Math.floor(d/86400)+'d ago'; };

function toast(msg, type='ok'){
  const t = el('div',{class:'toast '+(type==='err'?'err':'ok')}, esc(msg));
  $('#toasts').appendChild(t);
  setTimeout(()=>{ t.style.opacity='0'; t.style.transform='translateY(6px)'; setTimeout(()=>t.remove(),200); }, 3200);
}

async function api(path, opts){
  const res = await fetch(path, opts);
  if(res.status===401){ location.href='/login'; throw new Error('session expired'); }
  const ct = res.headers.get('content-type')||'';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if(!res.ok) throw new Error((data&&data.error)||res.statusText);
  return data;
}
const postJson = (p,b) => api(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});

function openModal(title, bodyHtml, footHtml){
  $('#modalBox').innerHTML = `<div class="head"><h3>${esc(title)}</h3><div class="grow" style="flex:1"></div><button class="icon-btn" id="mClose">${svg('x')}</button></div>
    <div class="body">${bodyHtml}</div>${footHtml?`<div class="foot">${footHtml}</div>`:''}`;
  $('#modal').classList.add('show');
  $('#mClose').onclick = closeModal;
  return $('#modalBox');
}
function closeModal(){ $('#modal').classList.remove('show'); }
$('#overlay').onclick = closeModal;
document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeModal(); });

const pageTitles = {dashboard:'Dashboard',files:'File Manager',editor:'Code Editor',terminal:'Terminal',databases:'Databases',scheduler:'Scheduled Tasks',security:'Directory Protection',backups:'Backups',activity:'Activity Log',settings:'Settings'};
let currentView = '';
function show(view){
  currentView = view;
  $$('.view').forEach(v=>v.classList.toggle('active', v.id==='view-'+view));
  $$('#nav a').forEach(a=>a.classList.toggle('active', a.dataset.view===view));
  $('#pageTitle').textContent = pageTitles[view]||view;
  $('#sidebar').classList.remove('open');
  location.hash = view;
  if(view==='dashboard') loadDashboard();
  if(view==='files') loadDir(state.path);
  if(view==='databases') loadDatabases();
  if(view==='scheduler') loadScheduler();
  if(view==='security') loadSecurity();
  if(view==='backups') loadBackups();
  if(view==='activity') loadActivity();
  if(view==='settings') loadSettings();
}
$$('#nav a').forEach(a=>a.onclick=()=>show(a.dataset.view));
$$('[data-goto]').forEach(b=>b.onclick=()=>show(b.dataset.goto));
$('#menuBtn').onclick = ()=>$('#sidebar').classList.toggle('open');
$('#viewSite').href = SITE_URL; $('#qaSite').href = SITE_URL;
$('#avatar').textContent = (ACCOUNT[0]||'A').toUpperCase();

/* ---------- metrics ---------- */
const cpuHist = [], memHist = [];
async function pollMetrics(){
  try{
    const m = await api('/api/metrics');
    $('#mCpu').textContent = m.cpu.toFixed(0)+'%';
    $('#mMem').textContent = m.mem.percent.toFixed(0)+'%';
    cpuHist.push(m.cpu); if(cpuHist.length>40) cpuHist.shift();
    memHist.push(m.mem.percent); if(memHist.length>40) memHist.shift();
    const c=$('#kCpu'), cb=$('#kCpuBar'), mb=$('#kMemBar');
    if(c){ c.textContent = m.cpu.toFixed(1)+'%'; cb.style.width = Math.min(100,m.cpu)+'%'; $('#kLoad').textContent='load '+(m.load||[]).join('  '); }
    if(mb){ mb.style.width = Math.min(100,m.mem.percent)+'%';
      $('#kMem').textContent = m.mem.percent.toFixed(0)+'%';
      $('#kMemSub').textContent = m.mem.used_h+' / '+m.mem.total_h; }
  }catch(e){}
}

/* ---------- dashboard ---------- */
async function loadDashboard(){
  try{
    const d = await api('/api/sysinfo');
    const i = d.info;
    $('#kCpu').textContent = d.metrics.cpu.toFixed(1)+'%';
    $('#kCpuBar').style.width = Math.min(100,d.metrics.cpu)+'%';
    $('#kLoad').textContent = 'load '+(i.load||[]).join('  ');
    $('#kMem').textContent = d.mem.percent.toFixed(0)+'%';
    $('#kMemBar').style.width = d.mem.percent+'%';
    $('#kMemSub').textContent = d.mem.used_h+' / '+d.mem.total_h;
    if(i.disk){ $('#kDisk').textContent = i.disk.percent+'%'; $('#kDiskBar').style.width=i.disk.percent+'%';
      $('#kDiskBar').parentElement.classList.toggle('red', i.disk.percent>90);
      $('#kDiskSub').textContent = i.disk.used_h+' used · '+i.disk.free_h+' free'; }
    const up = i.uptime; const hh=Math.floor(up/3600), mm=Math.floor(up%3600/60);
    $('#kUptime').textContent = (hh>0? hh+'h ':'')+mm+'m';
    $('#kPy').textContent = 'Python '+i.python+' · '+(i.cpus||1)+' cores';
    renderFeed($('#dashFeed'), d.activity);
  }catch(e){ toast(e.message,'err'); }
}
function renderFeed(node, items){
  if(!items || !items.length){ node.innerHTML = '<div class="empty" style="padding:20px">No activity yet</div>'; return; }
  node.innerHTML = items.map(a=>`<div class="item"><span class="act">${esc(a.action)}</span><span class="muted">${esc(a.detail||'')}</span><span class="when">${ago(a.t)}</span></div>`).join('');
}

/* ---------- file manager ---------- */
const state = { path:'', parent:null, sort:'name', dir:'asc', hidden:false, selected:new Set(), entries:[] };
function childPath(name){ return state.path ? state.path+'/'+name : name; }
async function loadDir(path){
  try{
    const q = `/api/list?path=${encodeURIComponent(path||'')}&sort=${state.sort}&dir=${state.dir}&hidden=${state.hidden?1:0}`;
    const d = await api(q);
    state.path=d.path; state.parent=d.parent; state.entries=d.entries; state.selected.clear();
    renderCrumbs(d.path); renderRows(d.entries, d.stats);
  }catch(e){ toast(e.message,'err'); }
}
function renderCrumbs(path){
  const c = $('#fCrumbs'); c.innerHTML='';
  const root = el('a',{},'root'); root.onclick=()=>loadDir(''); c.appendChild(root);
  if(path){ let acc=''; path.split('/').forEach(part=>{ acc = acc? acc+'/'+part : part;
    c.appendChild(el('span',{class:'sep'},'/')); const a=el('a',{},esc(part)); const t=acc; a.onclick=()=>loadDir(t); c.appendChild(a); }); }
}
function fileIcon(e){ return e.type==='dir' ? svg('folder') : (['png','jpg','jpeg','gif','webp','svg'].includes(e.ext)? svg('image') : svg('file')); }
function renderRows(entries, stats){
  const tb=$('#fRows'); tb.innerHTML='';
  if(!entries.length){ tb.innerHTML='<tr><td colspan="6"><div class="empty">'+svg('folder')+'<div>This folder is empty</div></div></td></tr>'; return; }
  entries.forEach(e=>{
    const tr=el('tr');
    const chk=`<input type="checkbox" class="chk rowchk" data-name="${esc(e.name)}">`;
    tr.appendChild(el('td',{},chk));
    const nameTd=el('td',{class:'name'},`<span class="ficon" style="color:${e.type==='dir'?'var(--accent)':'var(--blue)'}">${fileIcon(e)}</span><span>${esc(e.name)}</span>`);
    nameTd.onclick=()=> (e.type==='dir'? loadDir(childPath(e.name)) : openInEditor(childPath(e.name)));
    tr.appendChild(nameTd);
    tr.appendChild(el('td',{class:'dim'}, e.size_h));
    tr.appendChild(el('td',{class:'dim'}, e.mtime_h));
    tr.appendChild(el('td',{class:'dim mono'}, e.mode));
    const acts=el('td',{class:'actions'});
    const wrap=el('div',{class:'rowactions'});
    if(e.type==='dir'){
      wrap.append(mkBtn('Open',()=>loadDir(childPath(e.name))), mkBtn('Zip',()=>{location.href='/api/zip?path='+encodeURIComponent(childPath(e.name));}), mkBtn('Rename',()=>doRename(childPath(e.name),e.name)), mkBtn('Delete',()=>doDelete(childPath(e.name)),'danger'));
    } else {
      wrap.append(mkBtn(e.ext==='zip'?'Unzip':'Edit', e.ext==='zip'? ()=>doUnzip(childPath(e.name)) : ()=>openInEditor(childPath(e.name))),
        mkBtn('Download',()=>{location.href='/api/download?path='+encodeURIComponent(childPath(e.name));}),
        mkBtn('Rename',()=>doRename(childPath(e.name),e.name)), mkBtn('Delete',()=>doDelete(childPath(e.name)),'danger'));
    }
    wrap.appendChild(mkBtn('Info',()=>showInfo(childPath(e.name))));
    acts.appendChild(wrap); tr.appendChild(acts);
    tb.appendChild(tr);
  });
  $$('.rowchk',tb).forEach(c=>c.onchange=updateBulk);
}
function mkBtn(label,fn,cls=''){ const b=el('button',{class:'btn sm '+cls},esc(label)); b.onclick=(ev)=>{ev.stopPropagation();fn();}; return b; }
function updateBulk(){
  state.selected = new Set($$('.rowchk:checked').map(c=>c.dataset.name));
  $('#fBulk').style.display = state.selected.size? 'flex':'none';
  $('#fBulkCount').textContent = state.selected.size;
  $$('.rowchk').forEach(c=>{ c.closest('tr').style.background = c.checked? 'rgba(255,210,74,.06)':''; });
}
$('#fAll').onchange = e => { $$('.rowchk').forEach(c=>c.checked=e.target.checked); updateBulk(); };
$$('th[data-sort]').forEach(th=>th.onclick=()=>{ const s=th.dataset.sort; if(state.sort===s) state.dir=state.dir==='asc'?'desc':'asc'; else {state.sort=s;state.dir='asc';} loadDir(state.path); });
$('#fRefresh').onclick=()=>loadDir(state.path);
$('#fHidden').onchange=e=>{ state.hidden=e.target.checked; loadDir(state.path); };
$('#fUpload').onclick=()=>$('#fPicker').click();
$('#fPicker').onchange=e=>{ uploadFiles([...e.target.files]); e.target.value=''; };
$('#fZip').onclick=()=>{location.href='/api/zip?path='+encodeURIComponent(state.path);};
$('#fNewFolder').onclick=async()=>{ const n=prompt('New folder name:'); if(!n)return; try{await postJson('/api/mkdir',{path:state.path,name:n});toast('Folder created');loadDir(state.path);}catch(e){toast(e.message,'err');} };
$('#fNewFile').onclick=async()=>{ const n=prompt('New file name:'); if(!n)return; try{await postJson('/api/newfile',{path:state.path,name:n});toast('File created');loadDir(state.path);}catch(e){toast(e.message,'err');} };
async function uploadFiles(files){ if(!files.length)return; const fd=new FormData(); fd.append('path',state.path); files.forEach(f=>fd.append('files',f,f.name));
  try{ const d=await api('/api/upload',{method:'POST',body:fd}); toast('Uploaded '+d.saved.length+' file(s)'); loadDir(state.path);}catch(e){toast(e.message,'err');} }
async function doUnzip(p){ try{await postJson('/api/unzip',{path:p});toast('Extracted');loadDir(state.path);}catch(e){toast(e.message,'err');} }
async function doRename(p,cur){ const n=prompt('Rename to:',cur); if(!n||n===cur)return; try{await postJson('/api/rename',{path:p,newname:n});toast('Renamed');loadDir(state.path);}catch(e){toast(e.message,'err');} }
async function doDelete(p){ if(!confirm('Delete '+p+' ?'))return; try{await postJson('/api/delete',{path:p});toast('Deleted');loadDir(state.path);}catch(e){toast(e.message,'err');} }
async function showInfo(p){ try{ const d=await api('/api/stat?path='+encodeURIComponent(p)); const s=d.stat;
  openModal('Properties: '+s.name, `<div class="mono" style="line-height:2">
    <div><span class="muted">Path</span> ${esc(s.path)}</div><div><span class="muted">Type</span> ${s.type}</div>
    <div><span class="muted">Size</span> ${s.size_h}</div><div><span class="muted">Mode</span> ${s.mode}</div>
    <div><span class="muted">Modified</span> ${esc(s.mtime_h)}</div>${s.type==='dir'?`<div><span class="muted">Items</span> ${s.children}</div>`:''}
    </div>
    <div class="field" style="margin-top:14px"><label>Permissions (chmod)</label>
    <div class="toolbar"><input type="text" id="chmodVal" value="${s.mode}" style="width:100px">
    <button class="btn" id="chmodGo">Apply</button></div></div>`,
    `<button class="btn" onclick="closeModal()">Close</button>`);
  $('#chmodGo').onclick=async()=>{ try{ await postJson('/api/chmod',{path:p,mode:$('#chmodVal').value}); toast('Permissions updated'); closeModal(); loadDir(state.path);}catch(e){toast(e.message,'err');} };
 }catch(e){toast(e.message,'err');} }

$('#bDel').onclick=async()=>{ if(!state.selected.size)return; if(!confirm('Delete '+state.selected.size+' item(s)?'))return;
  try{ await postJson('/api/bulk',{action:'delete',paths:[...state.selected].map(childPath)}); toast('Deleted'); loadDir(state.path);}catch(e){toast(e.message,'err');} };
$('#bCopy').onclick=()=>bulkTransfer('copy');
$('#bMove').onclick=()=>bulkTransfer('move');
async function bulkTransfer(action){ const dst=prompt((action==='copy'?'Copy':'Move')+' to path (relative):', state.path); if(dst===null)return;
  try{ await postJson('/api/bulk',{action,dst,paths:[...state.selected].map(childPath)}); toast('Done'); loadDir(state.path);}catch(e){toast(e.message,'err');} }
$('#bDown').onclick=async()=>{ if(!state.selected.size)return;
  try{ const res=await fetch('/api/bulk_download',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:[...state.selected].map(childPath)})});
    if(!res.ok) throw new Error('download failed'); const blob=await res.blob(); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='lpanel-selection.zip'; a.click(); }
  catch(e){toast(e.message,'err');} };

$('#fSearch').addEventListener('keydown', async e=>{ if(e.key!=='Enter')return; const q=e.target.value.trim();
  if(!q){ loadDir(state.path); return; }
  try{ const d=await api('/api/search?q='+encodeURIComponent(q));
    const tb=$('#fRows'); tb.innerHTML='';
    if(!d.results.length){ tb.innerHTML='<tr><td colspan="6"><div class="empty">No matches</div></td></tr>'; return; }
    d.results.slice(0,150).forEach(r=>{ const tr=el('tr');
      tr.appendChild(el('td',{},''));
      const nameTd=el('td',{class:'name'},`<span class="ficon" style="color:var(--blue)">${svg('file')}</span><span>${esc(r.path)}</span>`);
      nameTd.onclick=()=>openInEditor(r.path); tr.appendChild(nameTd);
      tr.appendChild(el('td',{class:'dim'},r.size_h)); tr.appendChild(el('td',{class:'dim'},r.mtime_h)); tr.appendChild(el('td',{},''));
      const acts=el('td',{class:'actions'}); const wrap=el('div',{},''); wrap.appendChild(mkBtn('Edit',()=>openInEditor(r.path))); acts.appendChild(wrap); tr.appendChild(acts);
      tb.appendChild(tr); });
    $('#fBulk').style.display='none';
  }catch(e){toast(e.message,'err');} });

const fdrop=$('#fDrop');
fdrop.addEventListener('dragover',e=>{e.preventDefault();fdrop.classList.add('hot');});
fdrop.addEventListener('dragleave',()=>fdrop.classList.remove('hot'));
fdrop.addEventListener('drop',e=>{e.preventDefault();fdrop.classList.remove('hot');uploadFiles([...e.dataTransfer.files]);});

/* ---------- editor ---------- */
const ed = { path:'', handled:false };
async function openInEditor(p){ show('editor'); $('#edPath').textContent = p;
  try{ const d=await api('/api/raw?path='+encodeURIComponent(p));
    if(d.binary){ $('#edText').value=''; $('#edStat').textContent='Binary file — download instead'; $('#edText').placeholder='Binary file'; ed.path=''; updateGutter(); return; }
    ed.path=p; $('#edText').value=d.content; updateGutter(); updateStat(); toast('Opened '+p);
  }catch(e){toast(e.message,'err');} }
async function saveEditor(){ if(!ed.path){ toast('No file open','err'); return; }
  try{ await postJson('/api/save',{path:ed.path,content:$('#edText').value}); toast('Saved '+ed.path);}catch(e){toast(e.message,'err');} }
function updateGutter(){ const lines=$('#edText').value.split('\n').length; $('#edGutter').textContent=Array.from({length:Math.max(lines,1)},(_,i)=>i+1).join('\n'); syncScroll(); }
function updateStat(){ const v=$('#edText').value; $('#edStat').textContent=v.split('\n').length+' lines · '+v.length+' chars'; }
function syncScroll(){ $('#edGutter').scrollTop=$('#edText').scrollTop; }
$('#edText').addEventListener('input',()=>{updateGutter();updateStat();});
$('#edText').addEventListener('scroll',syncScroll);
$('#edSave').onclick=saveEditor;
$('#edDownload').onclick=()=>{ if(ed.path) location.href='/api/download?path='+encodeURIComponent(ed.path); };
$('#edOpen').onclick=()=>show('files');
document.addEventListener('keydown',e=>{ if((e.ctrlKey||e.metaKey)&&e.key==='s'){ e.preventDefault(); if($('#view-editor').classList.contains('active')) saveEditor(); } });

/* ---------- terminal ---------- */
const termHist=[]; let termHi=0;
function termAppend(html, cls=''){ const t=$('#term'); t.insertAdjacentHTML('beforeend', `<div class="${cls}">${html}</div>`); t.scrollTop=t.scrollHeight; }
$('#termClear').onclick=()=>{ $('#term').innerHTML=''; };
$('#termReset').onclick=async()=>{ try{await postJson('/api/terminal/reset',{}); termAppend('<span class="dim">[shell restarted]</span>'); }catch(e){toast(e.message,'err');} };
$('#termForm').onsubmit=async e=>{ e.preventDefault(); const inp=$('#termCmd'); const cmd=inp.value; if(!cmd.trim())return;
  termAppend(`<span class="ps1">$</span> <span class="cmd">${esc(cmd)}</span>`); termHist.push(cmd); termHi=termHist.length; inp.value='';
  try{ const d=await postJson('/api/terminal',{command:cmd}); if(d.output) termAppend(esc(d.output)); $('#termCwd').textContent=d.cwd; }
  catch(e){ termAppend(esc(e.message),'err'); } };
$('#termCmd').addEventListener('keydown',e=>{ if(e.key==='ArrowUp'){ if(termHi>0){termHi--; e.target.value=termHist[termHi]||'';} e.preventDefault(); }
  if(e.key==='ArrowDown'){ if(termHi<termHist.length-1){termHi++; e.target.value=termHist[termHi]||'';} else {termHi=termHist.length; e.target.value='';} e.preventDefault(); } });

/* ---------- databases ---------- */
let dbSelected=null;
async function loadDatabases(){
  try{ const d=await api('/api/db/list'); const list=$('#dbList');
    if(!d.databases.length){ list.innerHTML='<div class="empty">No databases yet</div>'; return; }
    list.innerHTML = d.databases.map(db=>`<div class="item" style="display:flex;align-items:center;gap:10px;padding:10px 6px;border-bottom:1px solid var(--line)">
      <span style="color:var(--blue)">${svg('database')}</span>
      <div style="flex:1"><div><b>${esc(db.name)}</b> <span class="dim">· ${db.tables} tables</span></div><div class="dim" style="font-size:12px">${db.size_h} · ${db.mtime_h}</div></div>
      <button class="btn sm" data-db="${esc(db.name)}">Open</button>
      <button class="btn sm danger" data-drop="${esc(db.name)}">Drop</button></div>`).join('');
    $$('[data-db]',list).forEach(b=>b.onclick=()=>selectDb(b.dataset.db));
    $$('[data-drop]',list).forEach(b=>b.onclick=async()=>{ if(!confirm('Drop database '+b.dataset.drop+'?'))return; try{await postJson('/api/db/drop',{db:b.dataset.drop}); toast('Dropped'); if(dbSelected===b.dataset.drop)dbSelected=null; loadDatabases();}catch(e){toast(e.message,'err');} });
  }catch(e){toast(e.message,'err');}
}
function selectDb(name){ dbSelected=name; $('#dbTitle').textContent='SQL console · '+name; $('#dbMsg').textContent=''; toast('Selected '+name); }
$('#dbNew').onclick=async()=>{ const n=prompt('Database name:'); if(!n)return; try{await postJson('/api/db/create',{name:n}); toast('Created'); loadDatabases();}catch(e){toast(e.message,'err');} };
$('#dbRefresh').onclick=loadDatabases;
$('#dbRun').onclick=async()=>{ if(!dbSelected){ toast('Open a database first','err'); return; } const sql=$('#dbSql').value;
  try{ const d=await postJson('/api/db/query',{db:dbSelected,sql}); $('#dbMsg').textContent = d.kind==='select'? d.rowcount+' rows': d.rowcount+' changes';
    if(d.columns.length){ $('#dbResult').innerHTML = '<div style="overflow:auto;max-height:340px"><table><thead><tr>'+d.columns.map(c=>`<th class="no-sort">${esc(c)}</th>`).join('')+'</tr></thead><tbody>'
      + d.rows.map(r=>'<tr>'+r.map(v=>`<td class="mono">${esc(v==null?'NULL':v)}</td>`).join('')+'</tr>').join('')+'</tbody></table></div>'; }
    else { $('#dbResult').innerHTML='<div class="dim">Query executed.</div>'; }
  }catch(e){ $('#dbMsg').textContent=e.message; } };

/* ---------- scheduler ---------- */
async function loadScheduler(){
  try{ const d=await api('/api/cron/list'); const tb=$('#scRows');
    if(!d.jobs.length){ tb.innerHTML='<tr><td colspan="6"><div class="empty">No scheduled tasks</div></td></tr>'; return; }
    tb.innerHTML=d.jobs.map(j=>`<tr>
      <td><b>${esc(j.name)}</b>${j.last_result?`<div class="dim" style="font-size:11px" title="${esc(j.last_result)}">${esc(j.last_result.split('\n')[0].slice(0,40))}</div>`:''}</td>
      <td class="mono dim">${esc(j.command)}</td><td>${j.interval}s</td><td>${j.enabled? (j.next_run||0)+'s':'—'}</td>
      <td><span class="chip" style="border-color:${j.enabled?'#2f5a44':'#5a2f2f'};color:${j.enabled?'var(--green)':'var(--red)'}">${j.enabled?'active':'paused'}</span></td>
      <td class="actions"><div class="rowactions">
        <button class="btn sm" data-run="${j.id}">Run</button>
        <button class="btn sm" data-toggle="${j.id}">${j.enabled?'Pause':'Resume'}</button>
        <button class="btn sm danger" data-del="${j.id}">Delete</button></div></td></tr>`).join('');
    $$('[data-run]',tb).forEach(b=>b.onclick=async()=>{ try{const r=await postJson('/api/cron/run',{id:b.dataset.run}); toast('Ran: '+(r.job? 'exit ok':'done')); loadScheduler();}catch(e){toast(e.message,'err');} });
    $$('[data-toggle]',tb).forEach(b=>b.onclick=async()=>{ try{await postJson('/api/cron/toggle',{id:b.dataset.toggle}); loadScheduler();}catch(e){toast(e.message,'err');} });
    $$('[data-del]',tb).forEach(b=>b.onclick=async()=>{ if(!confirm('Delete task?'))return; try{await postJson('/api/cron/delete',{id:b.dataset.del}); loadScheduler();}catch(e){toast(e.message,'err');} });
  }catch(e){toast(e.message,'err');}
}
$('#scAdd').onclick=async()=>{ const name=$('#scName').value, command=$('#scCmd').value, interval=parseInt($('#scInterval').value||'60');
  try{ await postJson('/api/cron/add',{name,command,interval}); toast('Task added'); $('#scName').value=''; $('#scCmd').value=''; loadScheduler();}catch(e){toast(e.message,'err');} };

/* ---------- security ---------- */
async function loadSecurity(){
  try{ const d=await api('/api/protect/list'); const tb=$('#secRows'); const keys=Object.keys(d.dirs);
    if(!keys.length){ tb.innerHTML='<tr><td colspan="3"><div class="empty">No protected directories</div></td></tr>'; return; }
    tb.innerHTML=keys.map(k=>`<tr><td class="mono">public_html/${esc(k)}</td><td>${esc(d.dirs[k].user)}</td>
      <td class="actions"><div class="rowactions"><button class="btn sm danger" data-rm="${esc(k)}">Remove</button></div></td></tr>`).join('');
    $$('[data-rm]',tb).forEach(b=>b.onclick=async()=>{ try{await postJson('/api/protect/remove',{path:b.dataset.rm}); toast('Unprotected'); loadSecurity();}catch(e){toast(e.message,'err');} });
  }catch(e){toast(e.message,'err');}
}
$('#secAdd').onclick=async()=>{ try{ await postJson('/api/protect/add',{path:$('#secPath').value,user:$('#secUser').value,password:$('#secPass').value}); toast('Directory protected'); $('#secPass').value=''; loadSecurity(); }catch(e){toast(e.message,'err');} };

/* ---------- backups ---------- */
async function loadBackups(){
  try{ const d=await api('/api/backup/list'); const tb=$('#bkRows');
    if(!d.backups.length){ tb.innerHTML='<tr><td colspan="4"><div class="empty">No backups yet</div></td></tr>'; return; }
    tb.innerHTML=d.backups.map(b=>`<tr><td><span style="color:var(--purple)">${svg('archive')}</span> ${esc(b.name)}</td><td class="dim">${b.size_h}</td><td class="dim">${b.mtime_h}</td>
      <td class="actions"><div class="rowactions">
        <a class="btn sm" href="/api/backup/download?name=${encodeURIComponent(b.name)}">Download</a>
        <button class="btn sm danger" data-bdel="${esc(b.name)}">Delete</button></div></td></tr>`).join('');
    $$('[data-bdel]',tb).forEach(x=>x.onclick=async()=>{ if(!confirm('Delete backup?'))return; try{await postJson('/api/backup/delete',{name:x.dataset.bdel}); toast('Deleted'); loadBackups();}catch(e){toast(e.message,'err');} });
  }catch(e){toast(e.message,'err');}
}
$('#bkCreate').onclick=async()=>{ toast('Creating backup...'); try{ const r=await postJson('/api/backup/create',{source:$('#bkSource').value}); toast('Backup created: '+r.name); loadBackups(); }catch(e){toast(e.message,'err');} };
$('#bkRefresh').onclick=loadBackups;
$('#qaBackup').onclick=async()=>{ toast('Creating backup...'); try{ const r=await postJson('/api/backup/create',{source:'root'}); toast('Backup created: '+r.name);}catch(e){toast(e.message,'err');} };

/* ---------- activity ---------- */
async function loadActivity(){ try{ const d=await api('/api/activity'); renderFeed($('#actFeed'), d.activity); }catch(e){toast(e.message,'err');} }
$('#actRefresh').onclick=loadActivity;

/* ---------- settings ---------- */
async function loadSettings(){
  try{ const d=await api('/api/settings'); const s=d.settings;
    $('#stAccount').value=s.account;
    $('#stInfo').innerHTML = `<div class="mono" style="line-height:2">
      <div><span class="muted">Panel</span> http://127.0.0.1:${s.panel_port}</div>
      <div><span class="muted">Site</span> ${esc(SITE_URL)}</div>
      <div><span class="muted">Root</span> ${esc(s.root)}</div>
      <div><span class="muted">Website</span> ${esc(s.site_dir)}</div>
      <div><span class="muted">Version</span> ${s.version} · Python ${s.python}</div></div>`;
  }catch(e){toast(e.message,'err');}
}
$('#stSaveAccount').onclick=async()=>{ try{ const r=await postJson('/api/settings/account',{account:$('#stAccount').value}); $('#avatar').textContent=(r.account[0]||'A').toUpperCase(); toast('Account updated');}catch(e){toast(e.message,'err');} };
$('#stSavePass').onclick=async()=>{ try{ await postJson('/api/settings/password',{current:$('#stCur').value,new:$('#stNew').value}); toast('Password updated'); $('#stCur').value='';$('#stNew').value=''; }catch(e){toast(e.message,'err');} };

/* ---------- boot ---------- */
hydrateIcons(document.body);
const initial = (location.hash||'#dashboard').slice(1);
show(pageTitles[initial]? initial : 'dashboard');
window.addEventListener('hashchange', ()=>{ const v=(location.hash||'').slice(1); if(pageTitles[v] && v!==currentView) show(v); });
pollMetrics(); setInterval(pollMetrics, 2500);
</script>
</body>
</html>"""


if __name__ == "__main__":
    main()
