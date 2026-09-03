"""Command-line entry point for the ZAP client operations.

Installed as `dintero-zap` (see pyproject.toml [project.scripts]).

Every subcommand takes `--zap <url>` (default `$ZAP_URL` or
`http://zap-proxy:8080`, matching the compose-network service name most
of our stacks use).
"""

import argparse

from . import client


def _add_zap_arg(parser):
    parser.add_argument(
        "--zap",
        default=client.DEFAULT_ZAP_URL,
        help=(
            "ZAP HTTP API base URL "
            f"(default: $ZAP_URL or {client.DEFAULT_ZAP_URL})"
        ),
    )


def main():
    parser = argparse.ArgumentParser(
        prog="dintero-zap",
        description=(
            "ZAP HTTP API client for CI/CD scan orchestration. "
            "Each subcommand wraps a small chunk of the ZAP REST API "
            "so buildspecs don't have to inline curl + jq loops."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_wait = sub.add_parser(
        "wait", help="Poll ZAP until it responds to /JSON/core/view/version/."
    )
    _add_zap_arg(p_wait)
    p_wait.add_argument("--timeout", type=int, default=120,
                        help="Seconds before giving up (default: 120).")

    p_import = sub.add_parser(
        "import-har",
        help="Import a HAR file into ZAP's site tree.",
    )
    _add_zap_arg(p_import)
    p_import.add_argument("--file", required=True,
                          help="HAR file path visible to the ZAP process.")

    p_drain = sub.add_parser(
        "drain-passive",
        help="Poll ZAP's passive-scan queue to zero.",
    )
    _add_zap_arg(p_drain)
    p_drain.add_argument("--timeout", type=int, default=600,
                         help="Seconds before soft-timeout (default: 600).")
    p_drain.add_argument("--poll-interval", type=int, default=5)

    p_active = sub.add_parser(
        "active-scan",
        help="Trigger + poll an active scan against a target URL.",
    )
    _add_zap_arg(p_active)
    p_active.add_argument("--target", required=True,
                          help="URL to attack (e.g., http://products:3000).")
    p_active.add_argument("--policy", default="API-Minimal",
                          help="Scan policy name (default: API-Minimal).")
    p_active.add_argument("--poll-interval", type=int, default=30,
                          help="Seconds between status polls (default: 30).")
    p_active.add_argument("--budget-iters", type=int, default=100,
                          help="Max poll iterations before soft-stop (default: 100).")

    p_dump = sub.add_parser(
        "dump",
        help="Write zap-alerts.json + zap-alerts-summary.json to a directory.",
    )
    _add_zap_arg(p_dump)
    p_dump.add_argument("--out", required=True, help="Output directory.")

    p_extract = sub.add_parser(
        "extract-messages",
        help=("Fetch raw request/response bytes for every alert at a given "
              "risk level. Useful for reproducing findings after ZAP is torn down."),
    )
    _add_zap_arg(p_extract)
    p_extract.add_argument("--alerts", required=True,
                           help="Path to a zap-alerts.json file.")
    p_extract.add_argument("--out", required=True, help="Output directory.")
    p_extract.add_argument("--risk", default="High",
                           help="Alert risk level to extract (default: High).")

    args = parser.parse_args()

    if args.command == "wait":
        client.wait(args.zap, args.timeout)
    elif args.command == "import-har":
        result = client.import_har(args.zap, args.file)
        print(result)
    elif args.command == "drain-passive":
        client.drain_passive(args.zap, args.timeout, args.poll_interval)
    elif args.command == "active-scan":
        client.active_scan(args.zap, args.target, args.policy,
                           args.poll_interval, args.budget_iters)
    elif args.command == "dump":
        client.dump_alerts(args.zap, args.out)
    elif args.command == "extract-messages":
        client.extract_messages(args.zap, args.alerts, args.out, args.risk)


if __name__ == "__main__":
    main()
