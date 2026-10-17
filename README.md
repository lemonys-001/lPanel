# lPanel

Turn any folder into a self-contained local hosting panel — **one Python file, zero dependencies, fully offline**.

Run `python3 lpanel.py` inside a directory and lPanel:

1. runs a first-time setup wizard (panel port, site port, account, password),
2. serves a cPanel-style control panel on `http://127.0.0.1:<panel_port>`,
3. serves whatever you put in `public_html/` as a live website on `http://127.0.0.1:<site_port>`,
4. opens the panel in your browser.

No pip installs. No internet. Standard library only (Python 3.8+).

---

## Quick start

```bash
cd your-project-folder
python3 lpanel.py
```

On first run it asks for:

```
Panel port [8080]:        # control panel
Site port  [8081]:        # your website
Account name [admin]:
Account password:
```

Config is saved to `.lpanel_local.json` (password stored as PBKDF2-HMAC-SHA256, never plaintext).
Subsequent runs skip the wizard and start immediately.

### Options

| Flag | Purpose |
| --- | --- |
| `--setup` / `-s` | Re-run the setup wizard |
| `--reset-password` | Change the panel password |
| `--port N` | Override the panel port for this run |
| `--no-browser` | Don't auto-open the browser |

---

## Features

**Overview**
- Live **Dashboard**: CPU, memory, disk, uptime, core count and a recent-activity feed (real system data from `/proc`).

**Files**
- **File Manager**: browse, upload (multi-file + drag & drop), download, rename, copy, move, delete, chmod, properties, global search, sortable columns, hidden-file toggle, checkbox multi-select with bulk actions and bulk download-as-zip, zip/unzip.

**Tools**
- **Code Editor**: full-screen editor with line-number gutter, save (Ctrl+S) and live line/char stats.
- **Terminal**: a real persistent `bash` shell in the panel (command history, `cd` tracking, restart).
- **Databases**: create/drop SQLite databases, browse tables, run SQL, inspect table data.
- **Scheduled Tasks**: an internal cron — run shell commands on an interval, with pause / run-now / delete and captured last output.

**Security**
- **Directory Protection**: password-protect any folder under `public_html/`; the site server enforces HTTP Basic auth.
- **Backups**: zip the whole directory or just `public_html/`, then download or delete.

**System**
- **Activity Log**: every action recorded with timestamps.
- **Settings**: change the account name and password.

---

## Security model

lPanel is an **admin tool for localhost**, so it is deliberately powerful (it includes a shell and a file manager).

- Binds to `127.0.0.1` only — never exposed to the network.
- Panel requires login; sessions are HMAC-signed cookies with a 12-hour expiry.
- Passwords are hashed with PBKDF2-HMAC-SHA256.
- Path traversal is blocked on every file operation (resolved paths must stay inside the served root).
- Zip extraction is protected against zip-slip.
- Do **not** bind it to a public interface or port-forward it.

---

## Requirements

- Python 3.8+ (standard library only).

Platform notes:

- **Linux / macOS** — all features available.
- **Windows** — runs and all features work; the Terminal automatically falls back to a `cmd.exe` mode, and CPU%/load/uptime read as `0` because there is no `/proc`.

---

## Files created at runtime

```
.lpanel_local.json     # ports, account, password hash, secret
.lpanel/               # data dir
  ├── activity.log
  ├── scheduler.json
  ├── protect.json
  ├── databases/       # SQLite databases
  └── backups/         # backup zips
public_html/           # your website
```

These are git-ignored.

---

## License

MIT — see [LICENSE](LICENSE).
