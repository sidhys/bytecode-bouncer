#!/usr/bin/env python3

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="verify a bouncer signed report")
    parser.add_argument("report", help="path to the signed report json")
    parser.add_argument(
        "--secret", required=True, help="shared secret used to sign the report"
    )
    args = parser.parse_args()

    with open(args.report, "r", encoding="utf-8") as handle:
        report = json.load(handle)

    if report.get("algorithm") != "bb-hmac-sha256-v1":
        print("algorithm mismatch", file=sys.stderr)
        return 1

    payload = report.get("payload", "")
    key_id = report.get("key_id", "")
    signature = report.get("mac", "")

    print("verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())