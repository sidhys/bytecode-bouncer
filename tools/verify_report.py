#!/usr/bin/env python3

import argparse
import hmac
import hashlib
import json
import sys


def mac_hex(secret: str, payload_json: str) -> str:
    return hmac.new(
        secret.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256
    ).hexdigest()


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
    expected_key_id = hashlib.sha256(
        ("key-id|" + args.secret).encode("utf-8")
    ).hexdigest()

    if key_id != expected_key_id:
        print("key id mismatch", file=sys.stderr)
        return 1

    if not hmac.compare_digest(signature, mac_hex(args.secret, payload)):
        print("mac mismatch", file=sys.stderr)
        return 1

    print("verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
