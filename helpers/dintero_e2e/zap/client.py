"""Thin ZAP HTTP API client for CI/CD scan orchestration.

All operations take a `zap_url` base (default env `ZAP_URL`, else
`http://zap-proxy:8080` — the docker-compose service name / port ZAP
typically listens on). Stdlib-only; safe to invoke from any container
that has network reach to ZAP.
"""

import json
import os
import time
import urllib.parse
import urllib.request


DEFAULT_ZAP_URL = os.environ.get("ZAP_URL", "http://zap-proxy:8080")


def _get_json(zap_url, path, timeout=30):
    url = zap_url.rstrip("/") + path
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def wait(zap_url, timeout_s=120):
    """Poll ZAP's version endpoint until healthy, or raise on timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            _get_json(zap_url, "/JSON/core/view/version/")
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError(f"ZAP not reachable at {zap_url} within {timeout_s}s")


def import_har(zap_url, file_path):
    """Import a HAR file into ZAP's site tree.

    `file_path` must be visible to the ZAP process — not the caller's
    filesystem. Typically arranged via a docker volume mount that both
    the E2E container (writes HAR) and the ZAP container (reads it) can
    see.
    """
    q = urllib.parse.urlencode({"filePath": file_path})
    return _get_json(zap_url, f"/JSON/exim/action/importHar/?{q}")


def drain_passive(zap_url, timeout_s=600, poll_interval_s=5):
    """Poll ZAP's passive-scan queue until it reaches zero (or soft-timeout)."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        remaining = _get_json(
            zap_url, "/JSON/pscan/view/recordsToScan/"
        )["recordsToScan"]
        print(f"[zap] passive queue: {remaining}")
        if str(remaining) == "0":
            return
        time.sleep(poll_interval_s)
    print(f"[zap] passive drain hit {timeout_s}s soft timeout")


def active_scan(
    zap_url,
    target,
    policy="API-Minimal",
    poll_interval_s=30,
    budget_iters=100,
):
    """Trigger an active scan against `target`, poll status, soft-stop
    if budget exceeded.

    Returns the scan id.
    """
    q = urllib.parse.urlencode(
        {
            "url": target,
            "recurse": "true",
            "inScopeOnly": "false",
            "scanPolicyName": policy,
        }
    )
    scan_id = _get_json(zap_url, f"/JSON/ascan/action/scan/?{q}")["scan"]
    print(f"[zap] active scan started ({policy}), id={scan_id}")

    for i in range(1, budget_iters + 1):
        status = _get_json(
            zap_url, f"/JSON/ascan/view/status/?scanId={scan_id}"
        )["status"]
        print(f"[zap] active scan: {status}% ({i}/{budget_iters})")
        if str(status) == "100":
            return scan_id
        time.sleep(poll_interval_s)

    print(f"[zap] active scan hit soft-timeout; stopping")
    _get_json(zap_url, f"/JSON/ascan/action/stop/?scanId={scan_id}")
    return scan_id


def dump_alerts(zap_url, out_dir):
    """Dump `zap-alerts.json` + `zap-alerts-summary.json` to `out_dir`."""
    os.makedirs(out_dir, exist_ok=True)
    for name, path in (
        ("zap-alerts.json", "/JSON/core/view/alerts/"),
        ("zap-alerts-summary.json", "/JSON/core/view/alertsSummary/"),
    ):
        target = os.path.join(out_dir, name)
        with urllib.request.urlopen(
            zap_url.rstrip("/") + path, timeout=30
        ) as r:
            with open(target, "wb") as f:
                f.write(r.read())
        print(f"[zap] wrote {target}")


def extract_messages(zap_url, alerts_path, out_dir, risk="High"):
    """For every alert at the given risk level, save its raw request +
    response bytes via ZAP's message API.

    Each output file contains a Message object with requestHeader,
    requestBody, responseHeader, responseBody — sufficient to curl-replay
    the exact request ZAP sent when it triggered the finding. Necessary
    because ZAP's container is normally torn down after the buildspec
    completes, taking the in-memory messages with it.
    """
    os.makedirs(out_dir, exist_ok=True)
    with open(alerts_path) as f:
        alerts = json.load(f).get("alerts", [])

    n = 0
    for a in alerts:
        if a.get("risk") != risk:
            continue
        mid = a.get("messageId")
        if not mid:
            continue
        try:
            with urllib.request.urlopen(
                f"{zap_url.rstrip('/')}/JSON/core/view/message/?id={mid}",
                timeout=30,
            ) as r:
                data = r.read()
        except Exception as e:
            print(f"[zap] failed to fetch messageId={mid}: {e}")
            continue
        fname = f"plugin-{a['pluginId']}-msg-{mid}.json"
        with open(os.path.join(out_dir, fname), "wb") as f:
            f.write(data)
        print(f"[zap] saved {a['alert']} messageId={mid} -> {fname}")
        n += 1

    print(f"[zap] captured {n} {risk}-severity request/response pairs")
