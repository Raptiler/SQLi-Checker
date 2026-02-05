# SQLi Checker PRO (Burp Suite Extension) — Jython 2.7

A practical **SQL Injection heuristic scanner** for Burp Suite that automatically generates request variants with payloads and compares responses (**status code** + **response body length**) to spot suspicious differences.

Built for real-world pentesting: broad injection coverage (params/headers/cookies/JSON/XML/multipart), **one-click manual scanning** from the context menu, and optional **in-scope Proxy auto-scanning** with deduplication.

---

## ✨ Key Features

### Manual scanning
- Right-click a request (e.g., in Repeater) → **`Check for SQLi PRO`**
- Runs in a background thread (doesn’t freeze Burp UI).

### Proxy auto-scanning
- **Enable PROXY scanning**:
  - auto-scans requests passing through Proxy,
  - optional **ONLY in-scope** filtering,
  - dedupes by **METHOD + endpoint (path)** to avoid scanning the same endpoint repeatedly.

### Injection coverage (where it tests)
Depending on UI toggles, the extension tests:

#### ✅ Headers (selected list)
- Injects into **header values** (suffix).
- Header allowlist is editable in the **Headers** tab.

#### ✅ Cookies
- Injects into **cookie values** parsed by Burp.

#### ✅ GET/POST params (Burp-parsed)
- Injects into **parameter values**.
- Injects into **full parameter names** (name injection).

#### ✅ Bracket segments inside parameter names
Supports bracketed names like:
- `a[b][c]`
- `a[][c]`

Modes:
- injects into **each bracket segment** individually (suffix),
- works for normal params and multipart `name="a[b][c]"`.

#### ✅ JSON (recursive + arrays)
- Injects into **keys and values**
- Recurses through:
  - objects (`dict`)
  - arrays (`list`)
- Non-string values are converted to strings before appending payloads.

#### ✅ XML (best-effort)
Injects into:
- **tag names**
- **attribute names**
- **attribute values**
- **text nodes**

Parser: `xml.etree.ElementTree` (if available).  
Some mutations are intentionally “first match” to avoid combinatorial explosion.

#### ✅ multipart/form-data (best-effort)
- Extracts `boundary` from `Content-Type`.
- Injects into:
  - multipart field `name="..."` (field name)
  - text-part values (not file parts)
- Supports bracket segments `[]` in multipart field names.

---

## 🧠 Detection Logic (Heuristic)

For each test target, the extension sends **two requests**:

- **REQ1**: `original + payload`
- **REQ2**: `original + payload + payload`

Then compares responses:

### Severity rules
- **CRITICAL**
  - if status flips **500 ↔ 200** (either direction)
- **MID**
  - if body length difference `abs(len1 - len2)` ≥ `min_length_diff`
  - default: `min_length_diff = 100`

Findings are reported to:
- the **Found** tab (results table),
- Burp **Scanner Issues** (as a `CustomScanIssue`).

---

## 🧩 UI Tabs

### Settings
Enable/disable specific modules:
- Param values / param names / bracket segments
- Headers / Cookies
- JSON / XML / multipart
- Proxy scanning + in-scope only

Actions:
- **Clear log**
- **Clear results table**
- **Clear scanned cache** (Proxy dedupe set)

### Payloads
- Payload list (one per line)
- Default examples: `'`, `"`, `%27`, `%22`, `` ` ``, `%2527`, `\\"`, `%5C%27`

### Headers
- Header names to test (one per line)
- Default includes: `User-Agent`, `X-Forwarded-For`, `Authorization`, `Origin`, `Referer`, `X-CSRF-Token`, etc.

### Found
Columns:
- URL
- Where (injection location)
- Mode (test type)
- Payload
- Status1→2
- Len1→2
- Level

### Log
Verbose output including:
- request id (REQ #),
- injection notes,
- request line,
- status/len/diff,
- optional short body previews.

---

## 🚀 Installation

1. Burp Suite → **Extender** → **Extensions** → **Add**
2. Type: **Python**
3. Select the `.py` file
4. Configure Jython 2.7 in **Extender → Options → Python Environment**.

---

## ▶️ Usage

### Manual (Repeater / Proxy history)
1. Open a request (e.g., Repeater)
2. Right-click → **Check for SQLi PRO**
3. Review **Found** and **Scanner → Issues**

### Proxy auto-scan
1. Enable **Enable PROXY scanning**
2. (Optional) Keep **Proxy scan ONLY in-scope URLs**
3. Browse the target — the extension scans new endpoints automatically.

---

## ⚠️ Notes & Limitations

- This is a **heuristic** — treat results as signals that require manual verification.
- XML and multipart handling is **best-effort** and may not cover every edge case.
- Proxy scanning dedupes by **METHOD + path**; if behavior differs by query/body parameters, consider clearing the scanned cache and re-testing.
- Can generate a lot of traffic — use responsibly, especially on production systems.

---

## 🛡️ Disclaimer

For authorized security testing only. You are responsible for ensuring you have permission to test the target systems.

