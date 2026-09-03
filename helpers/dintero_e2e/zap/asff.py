"""ZAP alerts JSON → ASFF findings.

Deterministic finding Id = sha256(pluginId + host + templated_path + param),
where templated_path comes from matching the alert URL against the OpenAPI
spec so run-to-run random E2E identifiers (accounts, catalog ids, ...) do
not perturb the hash.

Usage:
    python3 scripts/zap_to_asff.py --input alerts.json > findings.json
    python3 scripts/zap_to_asff.py --input alerts.json --min-confidence Medium

Only depends on the Python standard library.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

SEVERITY = {
    "High":          ("HIGH",          75),
    "Medium":        ("MEDIUM",        50),
    "Low":           ("LOW",           25),
    "Informational": ("INFORMATIONAL",  1),
}

# ZAP confidence -> ASFF Confidence (0-100). Kept distinct from Severity so a
# High-severity Medium-confidence finding still surfaces both facts.
ASFF_CONFIDENCE = {
    "Low":            25,
    "Medium":         50,
    "High":           75,
    "Confirmed":      90,
    "User Confirmed": 90,
}

# ASFF fields accepted by BatchImportFindings. `additionalProperties: false`
# semantics — anything outside these lists gets rejected server-side. Kept as
# whitelists here so a typo like Vulnerabilities.Cwe (the actual bug that hit
# us in CodeBuild) fails locally in the parser rather than at import time.
# Extend when the parser starts emitting new fields.
ASFF_TOP_LEVEL = frozenset([
    "SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId",
    "CreatedAt", "UpdatedAt", "Severity", "Title", "Description",
    "Resources", "Types",
    "Confidence", "Criticality", "SourceUrl", "Remediation",
    "Vulnerabilities", "Compliance", "ProductFields", "UserDefinedFields",
    "Note", "Workflow", "RelatedFindings",
    "FirstObservedAt", "LastObservedAt", "VerificationState", "Sample",
    "GeneratorDetails", "FindingProviderFields",
    "Action", "Malware", "Network", "Process", "ThreatIntelIndicators",
])
ASFF_SEVERITY = frozenset(["Label", "Normalized", "Original", "Product"])
ASFF_SEVERITY_LABELS = frozenset(
    ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
ASFF_REMEDIATION = frozenset(["Recommendation"])
ASFF_RECOMMENDATION = frozenset(["Text", "Url"])
ASFF_COMPLIANCE = frozenset(
    ["Status", "StatusReasons", "RelatedRequirements",
     "SecurityControlId", "AssociatedStandards"])
ASFF_VULN = frozenset([
    "Id", "VulnerablePackages", "Cvss", "RelatedVulnerabilities",
    "Vendor", "ReferenceUrls", "FixAvailable", "EpssScore",
    "ExploitAvailable", "LastKnownExploitAt", "CodeVulnerabilities",
])
ASFF_RESOURCE = frozenset([
    "Type", "Id", "Partition", "Region", "ResourceRole", "Tags",
    "DataClassification", "Details", "ApplicationName", "ApplicationArn",
])


def _check_keys(actual, allowed, ctx):
    unknown = sorted(set(actual) - allowed)
    if unknown:
        raise ValueError(
            f"ASFF validation: {ctx} has unknown fields {unknown}. "
            f"Either drop the fields from the parser or add them to the "
            f"allowlist at the top of {sys.argv[0]}.")


def validate_finding(f):
    _check_keys(f, ASFF_TOP_LEVEL, "top-level")
    sev = f.get("Severity") or {}
    _check_keys(sev, ASFF_SEVERITY, "Severity")
    if "Label" in sev and sev["Label"] not in ASFF_SEVERITY_LABELS:
        raise ValueError(
            f"ASFF validation: Severity.Label={sev['Label']!r} must be one of"
            f" {sorted(ASFF_SEVERITY_LABELS)}")
    if "Remediation" in f:
        _check_keys(f["Remediation"], ASFF_REMEDIATION, "Remediation")
        if "Recommendation" in f["Remediation"]:
            _check_keys(f["Remediation"]["Recommendation"],
                        ASFF_RECOMMENDATION, "Remediation.Recommendation")
    if "Compliance" in f:
        _check_keys(f["Compliance"], ASFF_COMPLIANCE, "Compliance")
    for i, v in enumerate(f.get("Vulnerabilities") or []):
        _check_keys(v, ASFF_VULN, f"Vulnerabilities[{i}]")
    for i, r in enumerate(f.get("Resources") or []):
        _check_keys(r, ASFF_RESOURCE, f"Resources[{i}]")


CONFIDENCE = {
    "False Positive": -1,
    "Low":             0,
    "Medium":          1,
    "High":            2,
    "Confirmed":       3,
    "User Confirmed":  3,
}


def load_spec_paths(spec_path):
    """Extract basePath and path templates from a Swagger/OpenAPI YAML file.

    Uses regex extraction so this script has no non-stdlib dependencies.
    Only reads the two things we actually need: basePath and the top-level
    keys under 'paths:'. If the spec ever grows a different indentation
    or format, replace this with a real YAML parse.
    """
    text = open(spec_path).read()
    base = ""
    m = re.search(r"^basePath:\s*(\S+)\s*$", text, re.M)
    if m:
        base = m.group(1).rstrip("/")

    templates = []
    in_paths = False
    for line in text.splitlines():
        if re.match(r"^paths:\s*$", line):
            in_paths = True
            continue
        if not in_paths:
            continue
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        m = re.match(r"^  (/\S+):\s*$", line)
        if m:
            templates.append(m.group(1))
    return base, templates


def compile_matchers(base, templates):
    """Return [(regex, full_template), ...] sorted longest-template-first."""
    compiled = []
    for t in templates:
        full = base + t
        pattern = re.escape(full)
        pattern = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", pattern)
        compiled.append((re.compile("^" + pattern + "$"), full))
    compiled.sort(key=lambda x: -len(x[1]))
    return compiled


def template_path(url, matchers):
    """Return (host, templated_path). Falls back to raw path if no match."""
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path.rstrip("/") or "/"
    for regex, template in matchers:
        if regex.match(path):
            return host, template
    return host, path


def finding_id(plugin_id, host, path, param):
    payload = f"{plugin_id}|{host}|{path}|{param}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def to_finding(alert, matchers, args, now):
    host, path = template_path(alert.get("url", ""), matchers)
    param  = alert.get("param") or ""
    plugin = alert.get("pluginId") or ""
    method = alert.get("method", "") or ""
    fid    = finding_id(plugin, host, path, param)

    risk = alert.get("risk", "Informational")
    label, normalized = SEVERITY.get(risk, ("INFORMATIONAL", 1))

    zap_conf = alert.get("confidence", "") or ""
    cwe      = alert.get("cweid") or ""
    src_url  = alert.get("url", "")

    # Merge ZAP's terse description with the plugin's `other` field, which is
    # where the actual "how it was detected" methodology lives (boolean-based
    # SQLi test, evidence, etc.). Attack/Evidence/InputVector go into
    # Resources.Details.Other (structured, machine-readable) instead of being
    # inlined here — downstream renderers can lay them out as they see fit.
    # ASFF caps Description at 1024 chars.
    desc_parts = []
    for k in ("description", "other"):
        v = (alert.get(k) or "").strip()
        if v:
            desc_parts.append(v)
    description = "\n\n".join(desc_parts)[:1024] or "ZAP finding"

    # GeneratorId encodes the repo so SH's console (which doesn't expose
    # ProductFields as a searchable field) can filter on prefix "zap-<repo>-"
    # for a single service or "zap-" for every ZAP-generated finding.
    generator_id = (f"zap-{args.repo}-plugin-{plugin}"
                    if args.repo else f"zap-plugin-{plugin}")

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": fid,
        "ProductArn": args.product_arn,
        "GeneratorId": generator_id,
        "AwsAccountId": args.account_id,
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": label, "Normalized": normalized},
        "Title": f"{alert.get('alert', 'ZAP finding')} on {path}"[:256],
        "Description": description,
        "SourceUrl": src_url[:512],
        "Resources": [{
            "Type": "Other",
            "Id": f"{host}{path}",
            "Details": {"Other": {
                "Method":      method,
                "Parameter":   param,
                "Confidence":  zap_conf,
                "PluginId":    plugin,
                "CweId":       f"CWE-{cwe}" if cwe else "",
                "InputVector": alert.get("inputVector", "") or "",
                "Attack":      (alert.get("attack") or "")[:1024],
                "Evidence":    (alert.get("evidence") or "")[:1024],
                "SourceUrl":   src_url[:1024],
            }},
        }],
        "Types": ["Software and Configuration Checks/Vulnerabilities"] +
                 ([f"Software and Configuration Checks/Vulnerabilities/CWE-{cwe}"]
                  if cwe else []),
    }

    if zap_conf in ASFF_CONFIDENCE:
        finding["Confidence"] = ASFF_CONFIDENCE[zap_conf]

    # ProductFields is a flat key-value bag the security team can filter on in
    # the SH console — e.g. Dintero:Tool = ZAP-DAST + Dintero:Repo = products.
    product_fields = {
        "Dintero:Tool":     "ZAP-DAST",
        "Dintero:PluginId": plugin,
    }
    if args.repo:
        product_fields["Dintero:Repo"] = args.repo
    if args.branch:
        product_fields["Dintero:Branch"] = args.branch
    finding["ProductFields"] = product_fields

    solution  = (alert.get("solution") or "").strip()
    reference = (alert.get("reference") or "").strip()
    if solution or reference:
        rec = {}
        if solution:
            # ASFF caps at 512, but a mid-word cut reads badly. Trim to the
            # last word boundary before the cap, add an ellipsis to signal
            # it was truncated. Full text is always visible via the SH
            # console (which renders the same field).
            if len(solution) > 512:
                trimmed = solution[:511]
                cut = trimmed.rfind(" ")
                if cut > 400:
                    trimmed = trimmed[:cut]
                rec["Text"] = trimmed.rstrip(",.;") + "…"
            else:
                rec["Text"] = solution
        if reference:
            rec["Url"] = reference.splitlines()[0][:2048]
        finding["Remediation"] = {"Recommendation": rec}

    # ASFF's Vulnerabilities[] block is for CVE/CPE-style dependency findings
    # (Cvss, VulnerablePackages, etc.). The CWE classification we care about
    # is already conveyed via Types = ".../CWE-89", which SH renders as a
    # clickable link — no Vulnerabilities entry needed.

    # ZAP tags carry OWASP / PCI / HIPAA framework references. Surface them as
    # ASFF Compliance.RelatedRequirements (max 32 items, 32 chars each).
    tags = alert.get("tags") or {}
    reqs = [k for k in tags
            if (k.startswith("OWASP_") or k.startswith("API_")
                or k in ("PCI_DSS", "HIPAA")) and len(k) <= 32]
    if reqs:
        finding["Compliance"] = {"RelatedRequirements": reqs[:32]}

    return finding


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", required=True,
                   help="ZAP alerts JSON (from /JSON/core/view/alerts/)")
    p.add_argument("--spec", default="app/products/api-spec/spec-products.yaml",
                   help="OpenAPI/Swagger spec used to template URL paths.")
    p.add_argument("--account-id", default="000000000000")
    p.add_argument("--product-arn",
                   default="arn:aws:securityhub:local::product/dintero/zap")
    p.add_argument("--min-confidence", default="High",
                   choices=["Low", "Medium", "High"],
                   help="Drop Low/Medium-risk alerts below this ZAP confidence"
                        " level. High-risk findings are always emitted"
                        " regardless of confidence — a Medium-confidence SQL"
                        " Injection is still worth a human's eyes.")
    p.add_argument("--now", default=None,
                   help="ISO 8601 timestamp; default: current UTC.")
    p.add_argument("--repo", default="",
                   help="Repo name, exposed as ProductFields[Dintero:Repo]"
                        " so SH can slice findings by service.")
    p.add_argument("--branch", default="",
                   help="Branch name, exposed as ProductFields[Dintero:Branch].")
    args = p.parse_args()

    now = args.now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    threshold = CONFIDENCE[args.min_confidence]

    base, templates = load_spec_paths(args.spec)
    matchers = compile_matchers(base, templates)

    payload = json.load(open(args.input))
    alerts = payload.get("alerts", payload) if isinstance(payload, dict) else payload

    findings = {}
    dropped = 0
    for a in alerts:
        risk = a.get("risk", "Informational")
        conf = a.get("confidence", "Low")
        if risk != "High" and CONFIDENCE.get(conf, 0) < threshold:
            dropped += 1
            continue
        f = to_finding(a, matchers, args, now)
        validate_finding(f)
        findings.setdefault(f["Id"], f)

    print(f"[zap-to-asff] {len(alerts)} alerts → {len(findings)} unique findings"
          f" (dropped {dropped} below min-confidence={args.min_confidence})",
          file=sys.stderr)

    json.dump({"Findings": list(findings.values())}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
