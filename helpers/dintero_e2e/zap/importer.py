"""Convert ZAP alerts to ASFF and upload to Security Hub in one step.

Wraps `dintero_e2e.zap.asff.build_findings` + boto3
`securityhub.batch_import_findings`. Auto-detects the AWS account via
STS and builds the default product ARN from account + region — the
buildspec only has to supply repo + input paths.

Skips the upload gracefully when the parser's confidence filter drops
every alert (avoids a spurious "no findings" API call).
"""

import json
import os

from . import asff


def import_findings(alerts_path, spec_path, repo, *,
                    branch=None, region="eu-west-1",
                    account_id=None, product_arn=None,
                    min_confidence="High", out_path=None):
    """Build ASFF findings and BatchImportFindings them to Security Hub.

    Deferred boto3 import so `dintero_e2e.zap.asff` stays stdlib-only —
    only pay the boto3 startup cost when we're actually uploading.
    """
    import boto3

    if account_id is None:
        account_id = boto3.client("sts").get_caller_identity()["Account"]

    if product_arn is None:
        product_arn = (
            f"arn:aws:securityhub:{region}:{account_id}"
            f":product/{account_id}/default"
        )

    if branch is None:
        # CodeBuild sets CODEBUILD_SOURCE_VERSION to `refs/heads/<name>`
        # for branch builds and to the commit sha for tag/PR builds. The
        # sh prefix is redundant in the ProductFields payload.
        raw = os.environ.get("CODEBUILD_SOURCE_VERSION", "")
        branch = raw[len("refs/heads/"):] if raw.startswith("refs/heads/") else raw

    findings, n_alerts, dropped = asff.build_findings(
        alerts_path, spec_path, account_id, product_arn,
        min_confidence=min_confidence, repo=repo, branch=branch,
    )
    print(f"[zap-import] {n_alerts} alerts → {len(findings)} unique findings"
          f" (dropped {dropped} below min-confidence={min_confidence})")

    if out_path:
        with open(out_path, "w") as f:
            json.dump({"Findings": findings}, f, indent=2)
        print(f"[zap-import] wrote {out_path}")

    if not findings:
        print("[securityhub] no findings to import (all dropped by parser filter)")
        return

    print(f"[securityhub] importing {len(findings)} findings to region={region}")
    sh = boto3.client("securityhub", region_name=region)
    resp = sh.batch_import_findings(Findings=findings)
    print(f"[securityhub] success={resp['SuccessCount']} "
          f"failed={resp['FailedCount']}")
    for f in resp.get("FailedFindings", []):
        print(f"[securityhub] failed: Id={f.get('Id')} "
              f"code={f.get('ErrorCode')} msg={f.get('ErrorMessage')}")
    if resp["FailedCount"]:
        raise SystemExit(1)
