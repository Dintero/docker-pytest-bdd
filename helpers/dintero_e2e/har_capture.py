"""HAR export of E2E-driven HTTP requests.

Feature-file usage — capture every HTTP call the suite makes into a HAR
1.2 document that ZAP (or Burp, or curl-replay tooling) can consume
after the E2E run completes.

    # conftest.py
    import pytest
    from dintero_e2e import har_capture

    @pytest.fixture(scope="session", autouse=True)
    def har_output_dump():
        yield
        if har_capture.enabled():
            har_capture.dump()

    # test_features.py or wherever HTTP calls happen
    from datetime import datetime
    from dintero_e2e import har_capture

    def _do_request(...):
        started = datetime.utcnow()
        response = requests.request(...)
        har_capture.capture(started, response)
        return response

Enable at run time by setting HAR_OUT=/path/to/output.har before pytest
starts. When unset the module is a no-op — `capture()` and `dump()`
early-return without touching disk.

Design note: this module is deliberately dependency-free (stdlib only)
so it doesn't drag anything onto the image's runtime deps.
"""

import base64
import json
import os
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlparse


_HAR_OUT = os.environ.get("HAR_OUT") or None
_entries = []


def enabled():
    return _HAR_OUT is not None


def _iso_utc(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _header_pairs(headers):
    return [{"name": str(k), "value": str(v)} for k, v in headers.items()]


def _query_pairs(url):
    q = urlparse(url).query
    return [
        {"name": k, "value": v}
        for k, v in parse_qsl(q, keep_blank_values=True)
    ]


def _mime_type(headers):
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v
    return ""


def _body_content(headers, body):
    """Return HAR-shaped {mimeType, text[, encoding]} for a request or response body.

    Text-ish content-types get inline text; everything else base64. Empty
    bodies return a stub with just the mimeType so the field exists.
    """
    mime = _mime_type(headers)
    if body is None or body == b"" or body == "":
        return {"mimeType": mime, "text": ""}

    text_ish = mime.startswith(("application/json", "text/", "application/xml"))
    if isinstance(body, bytes):
        if text_ish:
            try:
                return {"mimeType": mime, "text": body.decode("utf-8")}
            except UnicodeDecodeError:
                pass
        return {
            "mimeType": mime,
            "text": base64.b64encode(body).decode("ascii"),
            "encoding": "base64",
        }
    return {"mimeType": mime, "text": str(body)}


def capture(started_at, response):
    """Append a HAR entry constructed from a `requests` Response object.

    started_at is the wall-clock time just before requests.request(...) was
    called — response.elapsed only covers the round-trip.
    """
    if not enabled():
        return

    req = response.request
    elapsed_ms = int(response.elapsed.total_seconds() * 1000)

    req_content = _body_content(req.headers, req.body)
    req_body_size = -1
    if req.body is not None:
        req_body_size = len(
            req.body if isinstance(req.body, bytes) else str(req.body).encode()
        )

    resp_content = _body_content(response.headers, response.content)
    resp_body_size = len(response.content) if response.content else 0

    entry = {
        "startedDateTime": _iso_utc(started_at),
        "time": elapsed_ms,
        "request": {
            "method": req.method,
            "url": req.url,
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _header_pairs(req.headers),
            "queryString": _query_pairs(req.url),
            "headersSize": -1,
            "bodySize": req_body_size,
        },
        "response": {
            "status": response.status_code,
            "statusText": response.reason or "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _header_pairs(response.headers),
            "content": {**resp_content, "size": resp_body_size},
            "redirectURL": response.headers.get("Location", ""),
            "headersSize": -1,
            "bodySize": resp_body_size,
        },
        "cache": {},
        "timings": {"send": 0, "wait": elapsed_ms, "receive": 0},
    }

    # postData is only expected on requests that have a body — omit it
    # otherwise so HAR validators don't flag missing mimeType/text.
    if req.body is not None:
        entry["request"]["postData"] = req_content

    _entries.append(entry)


def dump():
    """Write accumulated entries to HAR_OUT. Called from session teardown."""
    if not enabled():
        return

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "dintero-e2e-har", "version": "0.1"},
            "entries": _entries,
        }
    }
    parent = os.path.dirname(_HAR_OUT)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(_HAR_OUT, "w", encoding="utf-8") as f:
        json.dump(har, f)
    print(f"\n[har] wrote {len(_entries)} entries to {_HAR_OUT}", flush=True)
