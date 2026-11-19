"""Loopback stand-ins for the two web services the tool talks to.

MockCatalog imitates the three Microsoft Update Catalog pages (search results table,
details page, download dialog) and the download host. MockFeed serves a LOLDrivers feed.
Both are real HTTP servers on 127.0.0.1, so the production HTTP code runs unmodified.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import threading
import urllib.parse

NEWEST_X64 = "11111111-1111-1111-1111-111111111111"     # 23.60.1.2, AMD64, lists the device's ID  -> the right answer
ARM64_ONLY = "22222222-2222-2222-2222-222222222222"     # 23.70.0.1, ARM64
OLDER = "33333333-3333-3333-3333-333333333333"          # 22.200.0.0
WIN11_ONLY = "44444444-4444-4444-4444-444444444444"     # 24.0.0.0, Windows 11 products only
NOT_A_DRIVER = "55555555-5555-5555-5555-555555555555"   # classification "Updates"
OTHER_DEVICE = "66666666-6666-6666-6666-666666666666"   # 23.65.0.0, details list a different hardware ID
USB_NIC = "77777777-7777-7777-7777-777777777777"        # 10.60.0.1 for USB\VID_0BDA&PID_8153

ROWS = {
    "PCI\\VEN_8086&DEV_2725": [
        (OLDER, "Intel - Net - 22.200.0.0", "Windows 10 and later drivers", "Drivers (Networking)", "3/1/2023", "22.200.0.0", 40000000),
        (NEWEST_X64, "Intel - Net - 23.60.1.2", "Windows 10 and later drivers, Windows 10 and later upgrade &amp; servicing drivers", "Drivers (Networking)", "10/20/2026", "23.60.1.2", 48211968),
        (ARM64_ONLY, "Intel - Net - 23.70.0.1", "Windows 10 and later drivers", "Drivers (Networking)", "11/1/2026", "23.70.0.1", 47000000),
        (WIN11_ONLY, "Intel - Net - 24.0.0.0", "Windows 11 Client, version 24H2 and later, Servicing Drivers", "Drivers (Networking)", "11/5/2026", "24.0.0.0", 49000000),
        (NOT_A_DRIVER, "2026-11 Cumulative Update mentioning PCI\\VEN_8086&amp;DEV_2725", "Windows 10", "Updates", "11/10/2026", "n/a", 900000000),
        (OTHER_DEVICE, "Intel - Net - 23.65.0.0", "Windows 10 and later drivers", "Drivers (Networking)", "10/25/2026", "23.65.0.0", 46000000),
    ],
    "USB\\VID_0BDA&PID_8153": [
        (USB_NIC, "Realtek - Net - 10.60.0.1", "Windows 10 and later drivers", "Drivers (Networking)", "6/2/2024", "10.60.0.1", 600000),
    ],
}
DETAILS = {
    NEWEST_X64: ("AMD64", "Intel", ["PCI\\VEN_8086&DEV_2725&SUBSYS_00248086", "PCI\\VEN_8086&DEV_2725"], "10/20/2026"),
    ARM64_ONLY: ("ARM64", "Intel", ["PCI\\VEN_8086&DEV_2725"], "11/1/2026"),
    OLDER: ("AMD64", "Intel", ["PCI\\VEN_8086&DEV_2725"], "3/1/2023"),
    WIN11_ONLY: ("AMD64", "Intel", ["PCI\\VEN_8086&DEV_2725"], "11/5/2026"),
    OTHER_DEVICE: ("AMD64", "Intel", ["PCI\\VEN_8086&DEV_2726", "PCI\\VEN_8086&DEV_51F0"], "10/25/2026"),
    USB_NIC: ("AMD64, X86", "Realtek", ["USB\\VID_0BDA&PID_8153&REV_3100", "USB\\VID_0BDA&PID_8153"], "6/2/2024"),
}


def search_page(rows) -> str:
    if not rows:
        return ("<html><body><div id='ctl00_catalogBody_noResultText'>We did not find any results for "
                "<span id='ctl00_catalogBody_searchString'>that</span></div></body></html>")
    body = []
    for i, (uid, title, products, classification, date, version, size) in enumerate(rows):
        body.append(f"""
<tr id="{uid}_R{i}">
  <td class="resultsbottomBorder resultsIconWidth" id="{uid}_C0_R{i}"><img src="Images/spacer.gif" alt="" /></td>
  <td class="resultsbottomBorder resultspadding" id="{uid}_C1_R{i}">
     <a id='{uid}_link' href="javascript:void(0);" onclick='goToDetails("{uid}");' class="contentTextItemSpacerNoBreakLink">
         {title}
     </a></td>
  <td class="resultsbottomBorder resultspadding" id="{uid}_C2_R{i}">{products}</td>
  <td class="resultsbottomBorder resultspadding" id="{uid}_C3_R{i}">{classification}</td>
  <td class="resultsbottomBorder resultspadding" id="{uid}_C4_R{i}">{date}</td>
  <td class="resultsbottomBorder resultspadding" id="{uid}_C5_R{i}">{version}</td>
  <td class="resultsbottomBorder resultspadding resultsSizeWidth" id="{uid}_C6_R{i}">
     <span id="{uid}_size">{size / 1048576:.1f} MB</span><span class="noDisplay" id="{uid}_originalSize">{size}</span></td>
  <td class="resultsbottomBorder resultsButtonWidth" id="{uid}_C7_R{i}">
     <input id="{uid}" class="flatBlueButtonDownload focus-only" type="button" value='Download' /></td>
</tr>""")
    return ("<html><head><script>var internal = 'x';</script></head><body>"
            "<table class=\"resultsBorder resultsBackGround\" id=\"ctl00_catalogBody_updateMatches\">"
            "<tr id=\"headerRow\"><th></th><th>Title</th><th>Products</th><th>Classification</th>"
            "<th>Last Updated</th><th>Version</th><th>Size</th><th>Download</th></tr>"
            + "".join(body) + "</table></body></html>")


def details_page(uid: str) -> str:
    arch, provider, ids, date = DETAILS[uid]
    hw = "".join(f"<div>{h.replace('&', '&amp;')}</div>" for h in ids)
    return f"""<html><head><style>.x{{}}</style></head><body>
<div id="titleDiv"><span id="ScopedViewHandler_titleText">Driver update</span></div>
<div id="dateDiv"><span id="ScopedViewHandler_labelDate_Separator" class="labelTitle">Last Modified:</span><span id="ScopedViewHandler_date">{date}</span></div>
<div id="archDiv"><span id="ScopedViewHandler_labelArchitecture_Separator" class="labelTitle">Architecture:</span> {arch} </div>
<div id="classificationDiv"><span class="labelTitle">Classification:</span> Drivers </div>
<div id="companyDiv"><span class="labelTitle">Company:</span> {provider} </div>
<div><span class="labelTitle">Driver Class:</span> Networking </div>
<div><span class="labelTitle">Driver Provider:</span> {provider} </div>
<div><span class="labelTitle">Version:</span> see table </div>
<div><span class="labelTitle">Version Date:</span> {date} </div>
<div id="driverhwIDs"><span class="labelTitle">Supported Hardware IDs:</span>{hw}</div>
</body></html>"""


class _Server:
    def __init__(self, handler):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class MockCatalog(_Server):
    def __init__(self, cab: bytes = b"MSCF" + b"\0" * 2048):
        self.cab, self.requests, self.fail = cab, [], False
        self.not_public: set[str] = set()     # update IDs answered like the live catalog: 302 -> ErrorInline.aspx
        self.headers: list[dict] = []          # request headers of every POST
        self.digest = base64.b64encode(hashlib.sha1(cab).digest()).decode()
        self.download_host_path = "/d/msdownload/update/driver/drvs/2026/10/driver_0123456789abcdef.cab"
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, body, status=200, ctype="text/html; charset=utf-8"):
                data = body if isinstance(body, bytes) else body.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(url.query)
                outer.requests.append(("GET", url.path, query))
                if outer.fail:
                    return self._send("Service Unavailable", 503)
                if url.path == "/Search.aspx":
                    return self._send(search_page(ROWS.get(query.get("q", [""])[0], [])))
                if url.path == "/ScopedViewInline.aspx":
                    return self._send(details_page(query["updateid"][0]))
                if url.path == "/ErrorInline.aspx":       # what following the redirect would show
                    return self._send("<html><body>We did not find any results.</body></html>")
                if url.path == outer.download_host_path:
                    return self._send(outer.cab, ctype="application/vnd.ms-cab-compressed")
                self._send("not found", 404)

            def do_POST(self):
                form = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
                outer.requests.append(("POST", self.path, form))
                outer.headers.append(dict(self.headers))
                if self.path != "/DownloadDialog.aspx" or "updateIDs" not in form:
                    return self._send("bad request", 400)
                if any(uid in form["updateIDs"][0] for uid in outer.not_public):
                    self.send_response(302)
                    self.send_header("Location", f"{outer.base}/ErrorInline.aspx?id=2380070948")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send(f"""<html><script>
var downloadInformation = new Array();
downloadInformation[0] = new Object();
downloadInformation[0].updateID ='{NEWEST_X64}';
downloadInformation[0].isHotFix =false;
downloadInformation[0].files = new Array();
downloadInformation[0].files[0] = new Object();
downloadInformation[0].files[0].url = '{outer.base}{outer.download_host_path}';
downloadInformation[0].files[0].digest = '{outer.digest}';
downloadInformation[0].files[0].architectures = 'AMD64';
downloadInformation[0].files[0].fileName = 'driver_0123456789abcdef.cab';
</script></html>""")
        super().__init__(Handler)


class MockFeed(_Server):
    """Serves whatever `body` holds at /api/drivers.json with `status`."""

    def __init__(self, body: bytes, status: int = 200):
        self.body, self.status, self.hits = body, status, 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.hits += 1
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)
        super().__init__(Handler)
        self.url = self.base + "/api/drivers.json"
