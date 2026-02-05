# -*- coding: utf-8 -*-
#
# SQLi Checker PRO (Burp Suite Extension) - Jython 2.7
#
# - Headers (selected list): value injection
# - Cookies: value injection
# - GET/POST params (Burp parsed): value + full-name injection
# - Bracket segments inside param names: a[b][c] -> a[b'<p>][c] (suffix), incl empty []
# - JSON: keys + values (recursive, arrays)
# - XML: tag names + attribute names + attribute values + text nodes (best-effort)
# - multipart/form-data: part name (incl bracket segs) + part value (text parts)
# - UI toggles + verbose logging (req id, injection, status/len/diff)
# - Proxy scanning (in-scope): auto-scan traffic, dedupe by METHOD + endpoint(path)
#

from burp import IBurpExtender, ITab, IContextMenuFactory, IScanIssue, IParameter, IProxyListener
from java.util import ArrayList
from threading import Thread, Lock
import traceback
import json
import copy
import re

from javax.swing import (
    JPanel, JTextArea, JTable, JScrollPane, JTabbedPane, JMenuItem,
    JCheckBox, JLabel, JButton
)
from javax.swing.table import DefaultTableModel
from javax.swing import BoxLayout
from java.awt import BorderLayout

try:
    import xml.etree.ElementTree as ET
except:
    ET = None


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IProxyListener):
    _BRACKET_SEG_RE = re.compile(r"\[([^\[\]]*)\]")  # matches [] too (inner can be "")

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("SQLi Checker PRO")

        self.min_length_diff = 100
        self.default_payloads = ["'", '"', "%27", "%22", "`", "%2527", '\\"', "%5C%27"]
        self.default_headers = ["User-Agent","X-Forwarded-For","X-User","X-Api-Key","Authorization","Referer","Origin","X-Real-IP","X-Forwarded-Host","X-Forwarded-Proto","X-Client-IP","X-Originating-IP","X-Remote-IP","Forwarded","X-Requested-With","X-CSRF-Token","X-Auth-Token","X-Access-Token","X-User-Id","X-Username"]

        self._req_counter = 0

        # Proxy scanning dedupe cache
        self._scanned_lock = Lock()
        self._scanned_keys = set()  # key = "METHOD scheme://host:port/path"

        self._init_ui()
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)

        # Proxy listener
        try:
            self._callbacks.registerProxyListener(self)
        except:
            self._log("[!] Failed to register proxy listener:\n%s" % traceback.format_exc())

        self._log("[+] SQLi Checker loaded")

    # ---------------- UI ----------------

    def _init_ui(self):
        self.tab = JTabbedPane()

        # Settings
        settings_panel = JPanel()
        settings_panel.setLayout(BoxLayout(settings_panel, BoxLayout.Y_AXIS))

        self.cb_test_param_values = JCheckBox("Test param VALUES (GET/POST/urlencoded/multipart text)", True)
        self.cb_test_param_names = JCheckBox("Test full param NAMES (GET/POST/urlencoded/multipart)", True)
        self.cb_test_bracket_segs = JCheckBox("Test bracket segments ( [] ) inside param names", True)
        self.cb_test_headers = JCheckBox("Test selected HEADERS", True)
        self.cb_test_cookies = JCheckBox("Test COOKIES (values)", True)
        self.cb_test_json = JCheckBox("Test JSON (keys + values)", True)
        self.cb_test_xml = JCheckBox("Test XML (tag/attr names + values + text)", True)
        self.cb_test_multipart = JCheckBox("Test multipart/form-data", True)

        settings_panel.add(self.cb_test_param_values)
        settings_panel.add(self.cb_test_param_names)
        settings_panel.add(self.cb_test_bracket_segs)
        settings_panel.add(self.cb_test_headers)
        settings_panel.add(self.cb_test_cookies)
        settings_panel.add(self.cb_test_json)
        settings_panel.add(self.cb_test_xml)
        settings_panel.add(self.cb_test_multipart)

        settings_panel.add(JLabel(" "))

        # Proxy scanning options
        self.cb_proxy_scan_enabled = JCheckBox("Enable PROXY scanning (auto-scan in-scope traffic)", False)
        self.cb_proxy_only_in_scope = JCheckBox("Proxy scan ONLY in-scope URLs", True)

        settings_panel.add(self.cb_proxy_scan_enabled)
        settings_panel.add(self.cb_proxy_only_in_scope)

        btns = JPanel()
        btns.setLayout(BoxLayout(btns, BoxLayout.X_AXIS))
        self.btn_clear_log = JButton("Clear log", actionPerformed=lambda e: self._clear_log())
        self.btn_clear_results = JButton("Clear results table", actionPerformed=lambda e: self._clear_results())
        self.btn_clear_scanned = JButton("Clear scanned cache", actionPerformed=lambda e: self._clear_scanned_cache())
        btns.add(self.btn_clear_log)
        btns.add(self.btn_clear_results)
        btns.add(self.btn_clear_scanned)

        settings_wrap = JPanel(BorderLayout())
        settings_wrap.add(settings_panel, BorderLayout.CENTER)
        settings_wrap.add(btns, BorderLayout.SOUTH)

        self.tab.addTab("Settings", settings_wrap)

        # Payloads
        self.payloads_area = JTextArea("\n".join(self.default_payloads), 10, 60)
        payload_panel = JPanel(BorderLayout())
        payload_panel.add(JLabel("Payloads (one per line):"), BorderLayout.NORTH)
        payload_panel.add(JScrollPane(self.payloads_area), BorderLayout.CENTER)
        self.tab.addTab("Payloads", payload_panel)

        # Headers
        self.headers_area = JTextArea("\n".join(self.default_headers), 10, 60)
        header_panel = JPanel(BorderLayout())
        header_panel.add(JLabel("Headers to test (one per line):"), BorderLayout.NORTH)
        header_panel.add(JScrollPane(self.headers_area), BorderLayout.CENTER)
        self.tab.addTab("Headers", header_panel)

        # Results
        self.table_model = DefaultTableModel(
            ["URL", "Where", "Mode", "Payload", "Status1->2", "Len1->2", "Level"], 0
        )
        self.result_table = JTable(self.table_model)
        results_panel = JPanel(BorderLayout())
        results_panel.add(JScrollPane(self.result_table), BorderLayout.CENTER)
        self.tab.addTab("Found", results_panel)

        # Log
        self.log_area = JTextArea("", 20, 100)
        self.log_area.setEditable(False)
        log_panel = JPanel(BorderLayout())
        log_panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)
        self.tab.addTab("Log", log_panel)

    def _clear_log(self):
        try:
            self.log_area.setText("")
        except:
            pass

    def _clear_results(self):
        try:
            while self.table_model.getRowCount() > 0:
                self.table_model.removeRow(0)
        except:
            pass

    def _clear_scanned_cache(self):
        try:
            with self._scanned_lock:
                self._scanned_keys = set()
            self._log("[*] Cleared scanned cache (proxy/memo).")
        except:
            self._log("[!] Failed to clear scanned cache:\n%s" % traceback.format_exc())

    def getTabCaption(self):
        return "SQLi Checker"

    def getUiComponent(self):
        return self.tab

    # ---------------- Context menu ----------------

    def createMenuItems(self, invocation):
        items = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if not messages or len(messages) == 0:
                return items

            item = JMenuItem("Check for SQLi PRO")
            item.addActionListener(lambda e, msg=messages[0]: self._run_sqli_scan(msg))
            items.add(item)
        except:
            self._log("[!] createMenuItems error:\n%s" % traceback.format_exc())
        return items

    def _run_sqli_scan(self, baseRequestResponse):
        try:
            analyzed = self._helpers.analyzeRequest(baseRequestResponse)
            key = self._make_scan_key(analyzed, baseRequestResponse.getHttpService())
            if self._is_already_scanned(key):
                self._log("[*] SKIP (already scanned): %s" % key)
                return

            self._mark_scanned(key)

            t = Thread(target=self._scan_worker, args=(baseRequestResponse,))
            t.daemon = True
            t.start()
        except:
            self._log("[!] Failed to start scan thread:\n%s" % traceback.format_exc())

    # ---------------- Proxy scanning ----------------

    def processProxyMessage(self, messageIsRequest, message):
        try:
            if not messageIsRequest:
                return

            if not self.cb_proxy_scan_enabled.isSelected():
                return

            rr = message.getMessageInfo()
            if rr is None:
                return

            analyzed = self._helpers.analyzeRequest(rr)
            if analyzed is None:
                return

            url_obj = analyzed.getUrl()
            if url_obj is None:
                return

            if self.cb_proxy_only_in_scope.isSelected():
                try:
                    if not self._callbacks.isInScope(url_obj):
                        return
                except:
                    return

            key = self._make_scan_key(analyzed, rr.getHttpService())
            if self._is_already_scanned(key):
                return

            self._mark_scanned(key)
            self._log("[*] PROXY auto-scan: %s" % key)

            t = Thread(target=self._scan_worker, args=(rr,))
            t.daemon = True
            t.start()

        except:
            try:
                self._log("[!] processProxyMessage error:\n%s" % traceback.format_exc())
            except:
                pass

    def _make_scan_key(self, analyzed, service):
        try:
            headers = analyzed.getHeaders()
            rl = headers[0] if headers and len(headers) > 0 else ""
            method = rl.split(" ", 1)[0].strip().upper() if " " in rl else "GET"

            u = analyzed.getUrl()
            s = str(u)

            if "?" in s:
                s = s.split("?", 1)[0]

            try:
                host = service.getHost() if service else None
                port = service.getPort() if service else None
                proto = service.getProtocol() if service else None
                if host and port and proto:
                    base = "%s://%s:%d" % (proto, host, port)
                    try:
                        path = u.getPath()
                        if path is None or path == "":
                            path = "/"
                    except:
                        path = "/"
                    s = base + path
            except:
                pass

            return "%s %s" % (method, s)
        except:
            return "UNKNOWN unknown://unknown/"

    def _is_already_scanned(self, key):
        try:
            with self._scanned_lock:
                return key in self._scanned_keys
        except:
            return False

    def _mark_scanned(self, key):
        try:
            with self._scanned_lock:
                self._scanned_keys.add(key)
        except:
            pass

    # ---------------- Logging ----------------

    def _log(self, msg):
        try:
            self._callbacks.printOutput(msg)
        except:
            pass
        try:
            self.log_area.append(msg + "\n")
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
        except:
            pass

    def _next_req_id(self):
        self._req_counter += 1
        return self._req_counter

    # ---------------- Scan worker ----------------

    def _scan_worker(self, baseRequestResponse):
        try:
            analyzed = self._helpers.analyzeRequest(baseRequestResponse)
            service = baseRequestResponse.getHttpService()
            headers = list(analyzed.getHeaders())
            url = str(analyzed.getUrl())

            body_bytes = baseRequestResponse.getRequest()[analyzed.getBodyOffset():]
            body_str = self._helpers.bytesToString(body_bytes)

            content_type = self._get_header_value(headers, "Content-Type")
            if content_type is None:
                content_type = ""

            payloads = self._get_payloads()
            headers_to_test = self._get_headers_to_test()

            self._log("[*] Start scan: %s" % url)
            self._log("[*] Content-Type: %s" % (content_type if content_type else "(none)"))
            self._log("[*] Payloads: %d | HeadersToTest: %d" % (len(payloads), len(headers_to_test)))

            # 1) headers
            if self.cb_test_headers.isSelected():
                for h in headers:
                    if ":" in h:
                        key, val = h.split(":", 1)
                        key = key.strip()
                        val = val.strip()
                        if key in headers_to_test:
                            for payload in payloads:
                                self._test_header_value(url, service, analyzed, headers, body_str, key, val, payload)

            # 2) parameters parsed by Burp (GET/POST/cookies)
            params = analyzed.getParameters()
            if params is None:
                params = []

            self._log("[*] Burp parsed params: %d" % len(params))

            for p in params:
                ptype = p.getType()
                pname = p.getName()

                if ptype == IParameter.PARAM_COOKIE:
                    if self.cb_test_cookies.isSelected() and self.cb_test_param_values.isSelected():
                        for payload in payloads:
                            self._test_cookie_value(url, service, analyzed, baseRequestResponse.getRequest(), p, payload)
                    continue

                if ptype in [IParameter.PARAM_URL, IParameter.PARAM_BODY]:
                    if self.cb_test_param_values.isSelected():
                        for payload in payloads:
                            self._test_param_value(url, service, analyzed, baseRequestResponse.getRequest(), p, payload)

                    if self.cb_test_param_names.isSelected():
                        for payload in payloads:
                            self._test_param_full_name(url, service, analyzed, baseRequestResponse.getRequest(), p, payload)

                    if self.cb_test_bracket_segs.isSelected() and self._has_brackets(pname):
                        segs = self._extract_bracket_segments(pname)
                        base_name = pname.split("[", 1)[0]
                        self._log("[*] Bracket param detected: %s | segs=%d" % (pname, len(segs)))

                        for seg_idx in range(len(segs)):
                            for payload in payloads:
                                new_name1 = self._build_name_with_injected_segment(base_name, segs, seg_idx, payload)
                                new_name2 = self._build_name_with_injected_segment(base_name, segs, seg_idx, payload + payload)
                                self._test_param_renamed(url, service, analyzed, baseRequestResponse.getRequest(),
                                                        p, new_name1, new_name2,
                                                        "bracket-seg idx=%d" % seg_idx, payload)

            # 3) JSON
            if self.cb_test_json.isSelected() and self._looks_like_json(content_type, body_str):
                self._test_json(url, service, analyzed, headers, body_str, payloads)

            # 4) XML  (FIX: parse from bytes first to avoid "unicode + encoding decl" crash)
            if self.cb_test_xml.isSelected() and self._looks_like_xml(content_type, body_str):
                self._test_xml(url, service, analyzed, headers, body_bytes, body_str, payloads)

            # 5) multipart
            if self.cb_test_multipart.isSelected() and self._looks_like_multipart(content_type):
                self._test_multipart(url, service, analyzed, headers, body_str, payloads, content_type)

            self._log("[*] Done scan: %s" % url)

        except:
            self._log("[!] Scan crashed:\n%s" % traceback.format_exc())

    # ---------------- Inputs ----------------

    def _get_payloads(self):
        try:
            return [p.strip() for p in self.payloads_area.getText().splitlines() if p.strip()]
        except:
            return []

    def _get_headers_to_test(self):
        try:
            return [h.strip() for h in self.headers_area.getText().splitlines() if h.strip()]
        except:
            return []

    # ---------------- Generic dual send ----------------

    def _send_dual(self, url, service, analyzed, req1, req2, where, mode, payload, inject_note, body_preview_1=None, body_preview_2=None):
        rid = self._next_req_id()

        try:
            rl1 = self._helpers.analyzeRequest(req1).getHeaders()[0]
        except:
            rl1 = "(req1 line?)"
        try:
            rl2 = self._helpers.analyzeRequest(req2).getHeaders()[0]
        except:
            rl2 = "(req2 line?)"

        self._log("[REQ #%d] %s | where=%s | mode=%s | payload=%s" % (rid, url, where, mode, payload))
        self._log("          inject: %s" % inject_note)
        self._log("          req1: %s" % rl1)
        self._log("          req2: %s" % rl2)
        if body_preview_1 is not None:
            self._log("          body1: %s" % self._short(body_preview_1))
        if body_preview_2 is not None:
            self._log("          body2: %s" % self._short(body_preview_2))

        resp1 = self._callbacks.makeHttpRequest(service, req1)
        resp2 = self._callbacks.makeHttpRequest(service, req2)
        if resp1 is None or resp2 is None or resp1.getResponse() is None or resp2.getResponse() is None:
            self._log("[REQ #%d] no response" % rid)
            return

        r1 = resp1.getResponse()
        r2 = resp2.getResponse()

        a1 = self._helpers.analyzeResponse(r1)
        a2 = self._helpers.analyzeResponse(r2)
        s1 = a1.getStatusCode()
        s2 = a2.getStatusCode()

        b1 = r1[a1.getBodyOffset():]
        b2 = r2[a2.getBodyOffset():]
        len1 = len(b1)
        len2 = len(b2)
        diff = abs(len1 - len2)

        self._log("[REQ #%d] status: %d vs %d | bodyLen: %d vs %d | diff=%d" % (rid, s1, s2, len1, len2, diff))

        level = None
        if (s1 == 500 and s2 == 200) or (s1 == 200 and s2 == 500):
            level = "CRITICAL"
        elif diff >= self.min_length_diff:
            level = "MID"

        if level:
            self.table_model.addRow([url, where, mode, payload, "%d->%d" % (s1, s2), "%d->%d" % (len1, len2), level])
            try:
                issue = CustomScanIssue(service, analyzed.getUrl(), [resp1, resp2], level,
                                        "SQLi heuristic hit. where=%s mode=%s payload=%s (status %d/%d len %d/%d)" %
                                        (where, mode, payload, s1, s2, len1, len2))
                self._callbacks.addScanIssue(issue)
            except:
                pass

    # ---------------- Headers ----------------

    def _test_header_value(self, url, service, analyzed, headers, body_str, name, val, payload):
        v1 = val + payload
        v2 = val + payload + payload

        h1 = []
        h2 = []
        for h in headers:
            if h.lower().startswith(name.lower() + ":"):
                h1.append("%s: %s" % (name, v1))
                h2.append("%s: %s" % (name, v2))
            else:
                h1.append(h)
                h2.append(h)

        req1 = self._helpers.buildHttpMessage(h1, self._helpers.stringToBytes(body_str))
        req2 = self._helpers.buildHttpMessage(h2, self._helpers.stringToBytes(body_str))
        self._send_dual(url, service, analyzed, req1, req2, "header:%s" % name, "header", payload,
                        "header value %s -> '%s' / '%s'" % (name, v1, v2))

    # ---------------- Cookies ----------------

    def _test_cookie_value(self, url, service, analyzed, base_req, param, payload):
        v = param.getValue()
        v1 = v + payload
        v2 = v + payload + payload
        p1 = self._helpers.buildParameter(param.getName(), v1, IParameter.PARAM_COOKIE)
        p2 = self._helpers.buildParameter(param.getName(), v2, IParameter.PARAM_COOKIE)
        req1 = self._helpers.updateParameter(base_req, p1)
        req2 = self._helpers.updateParameter(base_req, p2)
        self._send_dual(url, service, analyzed, req1, req2, "cookie:%s" % param.getName(), "cookie-value", payload,
                        "cookie value %s -> '%s' / '%s'" % (param.getName(), v1, v2))

    # ---------------- Param value ----------------

    def _test_param_value(self, url, service, analyzed, base_req, param, payload):
        v = param.getValue()
        v1 = v + payload
        v2 = v + payload + payload
        p1 = self._helpers.buildParameter(param.getName(), v1, param.getType())
        p2 = self._helpers.buildParameter(param.getName(), v2, param.getType())
        req1 = self._helpers.updateParameter(base_req, p1)
        req2 = self._helpers.updateParameter(base_req, p2)
        self._send_dual(url, service, analyzed, req1, req2, "param.value:%s" % param.getName(), "param-value", payload,
                        "param value %s -> '%s' / '%s'" % (param.getName(), v1, v2))

    # ---------------- Full param name ----------------

    def _test_param_full_name(self, url, service, analyzed, base_req, param, payload):
        name = param.getName()
        n1 = name + payload
        n2 = name + payload + payload

        tmp = self._helpers.removeParameter(base_req, param)
        req1 = self._helpers.addParameter(tmp, self._helpers.buildParameter(n1, param.getValue(), param.getType()))

        tmp2 = self._helpers.removeParameter(base_req, param)
        req2 = self._helpers.addParameter(tmp2, self._helpers.buildParameter(n2, param.getValue(), param.getType()))

        self._send_dual(url, service, analyzed, req1, req2, "param.name:%s" % name, "param-name", payload,
                        "param full name %s -> '%s' / '%s'" % (name, n1, n2))

    # ---------------- Bracket segments in param name ----------------

    def _has_brackets(self, name):
        return name is not None and ("[" in name and "]" in name)

    def _extract_bracket_segments(self, name):
        segs = []
        for m in self._BRACKET_SEG_RE.finditer(name):
            segs.append(m.group(1))
        return segs

    def _build_name_with_injected_segment(self, base_name, segments, idx, payload):
        out = base_name
        for i in range(len(segments)):
            inner = segments[i]
            if i == idx:
                inner = inner + payload
            out += "[%s]" % inner
        return out

    def _test_param_renamed(self, url, service, analyzed, base_req, param, new_name1, new_name2, mode, payload):
        tmp1 = self._helpers.removeParameter(base_req, param)
        req1 = self._helpers.addParameter(tmp1, self._helpers.buildParameter(new_name1, param.getValue(), param.getType()))

        tmp2 = self._helpers.removeParameter(base_req, param)
        req2 = self._helpers.addParameter(tmp2, self._helpers.buildParameter(new_name2, param.getValue(), param.getType()))

        self._send_dual(url, service, analyzed, req1, req2, "param.bracket:%s" % param.getName(), mode, payload,
                        "bracket rename '%s' -> '%s' / '%s'" % (param.getName(), new_name1, new_name2))

    # ---------------- JSON ----------------

    def _looks_like_json(self, content_type, body):
        ct = (content_type or "").lower()
        if "application/json" in ct:
            return True
        s = (body or "").strip()
        return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))

    def _test_json(self, url, service, analyzed, headers, body_str, payloads):
        try:
            original = json.loads(body_str)
        except:
            self._log("[!] JSON parse failed")
            return

        paths = self._json_paths(original)
        self._log("[*] JSON paths: %d" % len(paths))

        for path in paths:
            if self.cb_test_param_names.isSelected():
                for payload in payloads:
                    try:
                        j1 = copy.deepcopy(original)
                        j2 = copy.deepcopy(original)
                        if not self._json_inject(j1, path, payload, "key"):
                            continue
                        if not self._json_inject(j2, path, payload + payload, "key"):
                            continue
                        b1 = json.dumps(j1, ensure_ascii=False)
                        b2 = json.dumps(j2, ensure_ascii=False)
                        req1 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b1))
                        req2 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b2))
                        self._send_dual(url, service, analyzed, req1, req2,
                                        "json.key:%s" % self._path_str(path), "json-key", payload,
                                        "json key at %s" % self._path_str(path),
                                        body_preview_1=b1, body_preview_2=b2)
                    except:
                        continue

            if self.cb_test_param_values.isSelected():
                for payload in payloads:
                    try:
                        j1 = copy.deepcopy(original)
                        j2 = copy.deepcopy(original)
                        if not self._json_inject(j1, path, payload, "value"):
                            continue
                        if not self._json_inject(j2, path, payload + payload, "value"):
                            continue
                        b1 = json.dumps(j1, ensure_ascii=False)
                        b2 = json.dumps(j2, ensure_ascii=False)
                        req1 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b1))
                        req2 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b2))
                        self._send_dual(url, service, analyzed, req1, req2,
                                        "json.value:%s" % self._path_str(path), "json-value", payload,
                                        "json value at %s" % self._path_str(path),
                                        body_preview_1=b1, body_preview_2=b2)
                    except:
                        continue

    def _json_paths(self, obj, path=None):
        if path is None:
            path = []
        paths = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                paths.append(path + [k])
                paths.extend(self._json_paths(v, path + [k]))
        elif isinstance(obj, list):
            for i, it in enumerate(obj):
                paths.append(path + [i])
                paths.extend(self._json_paths(it, path + [i]))
        return paths

    def _json_inject(self, obj, path, payload, mode):
        if not path:
            return False
        ref = obj
        for p in path[:-1]:
            try:
                ref = ref[p]
            except:
                return False
        last = path[-1]

        if isinstance(ref, dict):
            if mode == "key":
                if last not in ref:
                    return False
                nk = str(last) + payload
                ref[nk] = ref[last]
                del ref[last]
                return True
            if mode == "value":
                if last not in ref:
                    return False
                v = ref[last]
                if isinstance(v, basestring):
                    ref[last] = v + payload
                else:
                    ref[last] = str(v) + payload
                return True

        if isinstance(ref, list):
            if not isinstance(last, int) or last < 0 or last >= len(ref):
                return False
            if mode != "value":
                return False
            v = ref[last]
            if isinstance(v, basestring):
                ref[last] = v + payload
            else:
                ref[last] = str(v) + payload
            return True

        return False

    def _path_str(self, path):
        try:
            return ".".join([str(x) for x in path])
        except:
            return str(path)

    # ---------------- XML (best-effort) ----------------

    def _looks_like_xml(self, content_type, body):
        ct = (content_type or "").lower()
        if "xml" in ct:
            return True
        s = (body or "").strip()
        return s.startswith("<") and s.endswith(">")

    def _test_xml(self, url, service, analyzed, headers, body_bytes, body_str, payloads):
        if ET is None:
            self._log("[!] XML lib missing")
            return

        # FIX: prefer parsing from bytes to avoid unicode+encoding-decl crash in Py2/Jython
        base_root = None
        try:
            if body_bytes is not None and len(body_bytes) > 0:
                base_root = ET.fromstring(body_bytes)
        except:
            base_root = None

        if base_root is None:
            try:
                # fallback: strip xml declaration if present (best-effort)
                s = body_str or ""
                s = s.lstrip(u"\ufeff").lstrip("\xef\xbb\xbf")  # handle BOM-ish
                s2 = re.sub(r'^\s*<\?xml[^>]*\?>\s*', '', s, flags=re.IGNORECASE)
                base_root = ET.fromstring(s2)
            except:
                self._log("[!] XML parse failed")
                return

        tags = []
        for e in base_root.iter():
            tags.append(e.tag)

        # tag rename all occurrences (simple)
        if self.cb_test_param_names.isSelected():
            for tag in tags:
                for payload in payloads:
                    try:
                        # parse fresh root for each mutation (use bytes if possible)
                        r1 = None
                        r2 = None
                        try:
                            if body_bytes is not None and len(body_bytes) > 0:
                                r1 = ET.fromstring(body_bytes)
                                r2 = ET.fromstring(body_bytes)
                        except:
                            r1 = None
                            r2 = None
                        if r1 is None or r2 is None:
                            s = body_str or ""
                            s = s.lstrip(u"\ufeff").lstrip("\xef\xbb\xbf")
                            s2 = re.sub(r'^\s*<\?xml[^>]*\?>\s*', '', s, flags=re.IGNORECASE)
                            r1 = ET.fromstring(s2)
                            r2 = ET.fromstring(s2)

                        self._xml_rename_tag_all(r1, tag, tag + payload)
                        self._xml_rename_tag_all(r2, tag, tag + payload + payload)
                        b1 = ET.tostring(r1)
                        b2 = ET.tostring(r2)
                        req1 = self._helpers.buildHttpMessage(headers, b1)
                        req2 = self._helpers.buildHttpMessage(headers, b2)
                        self._send_dual(url, service, analyzed, req1, req2,
                                        "xml.tag:%s" % tag, "xml-tag", payload,
                                        "xml tag rename %s" % tag)
                    except:
                        continue

        # attributes + text (first-match, to avoid explosion)
        for e in base_root.iter():
            for an in list(e.attrib.keys()):
                av = e.attrib.get(an, "")
                if self.cb_test_param_names.isSelected():
                    for payload in payloads:
                        try:
                            r1 = None
                            r2 = None
                            try:
                                if body_bytes is not None and len(body_bytes) > 0:
                                    r1 = ET.fromstring(body_bytes)
                                    r2 = ET.fromstring(body_bytes)
                            except:
                                r1 = None
                                r2 = None
                            if r1 is None or r2 is None:
                                s = body_str or ""
                                s = s.lstrip(u"\ufeff").lstrip("\xef\xbb\xbf")
                                s2 = re.sub(r'^\s*<\?xml[^>]*\?>\s*', '', s, flags=re.IGNORECASE)
                                r1 = ET.fromstring(s2)
                                r2 = ET.fromstring(s2)

                            if not self._xml_rename_attr_first(r1, e.tag, an, an + payload):
                                continue
                            if not self._xml_rename_attr_first(r2, e.tag, an, an + payload + payload):
                                continue
                            b1 = ET.tostring(r1)
                            b2 = ET.tostring(r2)
                            req1 = self._helpers.buildHttpMessage(headers, b1)
                            req2 = self._helpers.buildHttpMessage(headers, b2)
                            self._send_dual(url, service, analyzed, req1, req2,
                                            "xml.attr.name:%s@%s" % (e.tag, an), "xml-attr-name", payload,
                                            "xml attr rename %s@%s" % (e.tag, an))
                        except:
                            continue

                if self.cb_test_param_values.isSelected():
                    for payload in payloads:
                        try:
                            r1 = None
                            r2 = None
                            try:
                                if body_bytes is not None and len(body_bytes) > 0:
                                    r1 = ET.fromstring(body_bytes)
                                    r2 = ET.fromstring(body_bytes)
                            except:
                                r1 = None
                                r2 = None
                            if r1 is None or r2 is None:
                                s = body_str or ""
                                s = s.lstrip(u"\ufeff").lstrip("\xef\xbb\xbf")
                                s2 = re.sub(r'^\s*<\?xml[^>]*\?>\s*', '', s, flags=re.IGNORECASE)
                                r1 = ET.fromstring(s2)
                                r2 = ET.fromstring(s2)

                            if not self._xml_set_attr_value_first(r1, e.tag, an, str(av) + payload):
                                continue
                            if not self._xml_set_attr_value_first(r2, e.tag, an, str(av) + payload + payload):
                                continue
                            b1 = ET.tostring(r1)
                            b2 = ET.tostring(r2)
                            req1 = self._helpers.buildHttpMessage(headers, b1)
                            req2 = self._helpers.buildHttpMessage(headers, b2)
                            self._send_dual(url, service, analyzed, req1, req2,
                                            "xml.attr.value:%s@%s" % (e.tag, an), "xml-attr-value", payload,
                                            "xml attr value %s@%s" % (e.tag, an))
                        except:
                            continue

            if self.cb_test_param_values.isSelected():
                if e.text is not None and str(e.text).strip() != "":
                    for payload in payloads:
                        try:
                            r1 = None
                            r2 = None
                            try:
                                if body_bytes is not None and len(body_bytes) > 0:
                                    r1 = ET.fromstring(body_bytes)
                                    r2 = ET.fromstring(body_bytes)
                            except:
                                r1 = None
                                r2 = None
                            if r1 is None or r2 is None:
                                s = body_str or ""
                                s = s.lstrip(u"\ufeff").lstrip("\xef\xbb\xbf")
                                s2 = re.sub(r'^\s*<\?xml[^>]*\?>\s*', '', s, flags=re.IGNORECASE)
                                r1 = ET.fromstring(s2)
                                r2 = ET.fromstring(s2)

                            if not self._xml_set_text_first(r1, e.tag, str(e.text) + payload):
                                continue
                            if not self._xml_set_text_first(r2, e.tag, str(e.text) + payload + payload):
                                continue
                            b1 = ET.tostring(r1)
                            b2 = ET.tostring(r2)
                            req1 = self._helpers.buildHttpMessage(headers, b1)
                            req2 = self._helpers.buildHttpMessage(headers, b2)
                            self._send_dual(url, service, analyzed, req1, req2,
                                            "xml.text:%s" % e.tag, "xml-text", payload,
                                            "xml text %s" % e.tag)
                        except:
                            continue

    def _xml_rename_tag_all(self, root, old_tag, new_tag):
        for el in root.iter():
            if el.tag == old_tag:
                el.tag = new_tag

    def _xml_rename_attr_first(self, root, tag, old_attr, new_attr):
        for el in root.iter():
            if el.tag == tag and old_attr in el.attrib:
                el.attrib[new_attr] = el.attrib[old_attr]
                del el.attrib[old_attr]
                return True
        return False

    def _xml_set_attr_value_first(self, root, tag, attr, new_val):
        for el in root.iter():
            if el.tag == tag and attr in el.attrib:
                el.attrib[attr] = new_val
                return True
        return False

    def _xml_set_text_first(self, root, tag, new_text):
        for el in root.iter():
            if el.tag == tag and el.text is not None and str(el.text).strip() != "":
                el.text = new_text
                return True
        return False

    # ---------------- multipart/form-data (best-effort) ----------------

    def _looks_like_multipart(self, content_type):
        ct = (content_type or "").lower()
        return "multipart/form-data" in ct and "boundary=" in ct

    def _test_multipart(self, url, service, analyzed, headers, body_str, payloads, content_type):
        m = re.search(r"boundary=([^;]+)", content_type, re.IGNORECASE)
        if not m:
            self._log("[!] multipart: boundary not found")
            return
        boundary = m.group(1).strip().strip('"')
        if boundary == "":
            self._log("[!] multipart: empty boundary")
            return

        boundary_line = "--" + boundary
        parts = body_str.split(boundary_line)

        self._log("[*] multipart parts chunks: %d" % len(parts))

        for chunk in parts:
            if "Content-Disposition:" not in chunk:
                continue
            if "\r\n\r\n" not in chunk:
                continue

            head, content = chunk.split("\r\n\r\n", 1)
            nm = re.search(r'name="([^"]+)"', head)
            if not nm:
                continue
            field_name = nm.group(1)
            is_file = ("filename=" in head)

            if self.cb_test_param_names.isSelected():
                for payload in payloads:
                    n1 = field_name + payload
                    n2 = field_name + payload + payload
                    b1 = self._multipart_replace_name(body_str, field_name, n1)
                    b2 = self._multipart_replace_name(body_str, field_name, n2)
                    if b1 is None or b2 is None:
                        continue
                    req1 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b1))
                    req2 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b2))
                    self._send_dual(url, service, analyzed, req1, req2,
                                    "multipart.name:%s" % field_name, "multipart-name", payload,
                                    "multipart name %s -> %s/%s" % (field_name, n1, n2),
                                    body_preview_1=b1, body_preview_2=b2)

            if self.cb_test_bracket_segs.isSelected() and self._has_brackets(field_name):
                segs = self._extract_bracket_segments(field_name)
                base_name = field_name.split("[", 1)[0]
                for seg_idx in range(len(segs)):
                    for payload in payloads:
                        n1 = self._build_name_with_injected_segment(base_name, segs, seg_idx, payload)
                        n2 = self._build_name_with_injected_segment(base_name, segs, seg_idx, payload + payload)
                        b1 = self._multipart_replace_name(body_str, field_name, n1)
                        b2 = self._multipart_replace_name(body_str, field_name, n2)
                        if b1 is None or b2 is None:
                            continue
                        req1 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b1))
                        req2 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b2))
                        self._send_dual(url, service, analyzed, req1, req2,
                                        "multipart.bracket:%s" % field_name, "multipart-bracket", payload,
                                        "multipart bracket rename %s -> %s/%s" % (field_name, n1, n2),
                                        body_preview_1=b1, body_preview_2=b2)

            if (not is_file) and self.cb_test_param_values.isSelected():
                for payload in payloads:
                    b1 = self._multipart_inject_value(body_str, field_name, payload)
                    b2 = self._multipart_inject_value(body_str, field_name, payload + payload)
                    if b1 is None or b2 is None:
                        continue
                    req1 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b1))
                    req2 = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(b2))
                    self._send_dual(url, service, analyzed, req1, req2,
                                    "multipart.value:%s" % field_name, "multipart-value", payload,
                                    "multipart value inject %s" % field_name,
                                    body_preview_1=b1, body_preview_2=b2)

    def _multipart_replace_name(self, body_str, old_name, new_name):
        needle = 'name="%s"' % old_name
        pos = body_str.find(needle)
        if pos < 0:
            return None
        repl = 'name="%s"' % new_name
        return body_str[:pos] + repl + body_str[pos + len(needle):]

    def _multipart_inject_value(self, body_str, field_name, payload):
        needle = 'name="%s"' % field_name
        pos = body_str.find(needle)
        if pos < 0:
            return None
        p = body_str.find("\r\n\r\n", pos)
        if p < 0:
            return None
        content_start = p + 4
        end = body_str.find("\r\n--", content_start)
        if end < 0:
            return None
        content = body_str[content_start:end]
        return body_str[:content_start] + (content + payload) + body_str[end:]

    # ---------------- Utils ----------------

    def _get_header_value(self, headers, name):
        ln = name.lower()
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                if k.strip().lower() == ln:
                    return v.strip()
        return None

    def _short(self, s, maxlen=160):
        try:
            if s is None:
                return ""
            if len(s) <= maxlen:
                return s
            return s[:maxlen] + "...(truncated)"
        except:
            return "(preview failed)"


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, severity, detail):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._severity = severity
        self._detail = detail

    def getUrl(self): return self._url
    def getIssueName(self): return "SQL Injection (" + self._severity + ")"
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return "High" if self._severity == "CRITICAL" else "Medium"
    def getConfidence(self): return "Firm"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._httpMessages
    def getHttpService(self): return self._httpService
