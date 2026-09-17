#!/usr/bin/env python3
"""Launch a real JVM and check reports against the class files it receives."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("java", "agent", "classes", "replacement", "java-agent", "reports"):
        parser.add_argument("--" + name, type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--mode", default="change", choices=("change", "clean"))
    args = parser.parse_args()
    args.reports.mkdir(parents=True, exist_ok=True)
    report = Path(tempfile.mkdtemp(prefix=args.mode + "-", dir=args.reports)) / "report.jsonl"
    original = args.classes / "bouncer/demo/Score.class"
    replacement = args.replacement / "bouncer/demo/Score.class"
    command = [str(args.java), "-Xcheck:jni", f"-agentpath:{args.agent}=output={report}"]
    if args.mode == "change":
        command.append(f"-javaagent:{args.java_agent}")
    command += ["-cp", str(args.classes), "bouncer.demo.Demo"]
    if args.mode == "change":
        command.append(str(replacement))
    print("Starting JVM (" + args.mode + ")", flush=True)
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=30)
    print(result.stdout, end="", flush=True)
    if result.returncode:
        raise RuntimeError(f"JVM exited with code {result.returncode}")
    summary = re.search(r"agent unloaded .*changes=(\d+) errors=(\d+)", result.stdout)
    if summary is None or int(summary[2]) != 0:
        raise RuntimeError("The detector did not complete successfully")
    if "WARNING in native method" in result.stdout:
        raise RuntimeError("The JVM reported incorrect JNI usage")
    if not report.is_file():
        raise RuntimeError("The agent did not create its report file")
    events = [json.loads(line) for line in report.read_text().splitlines() if line.strip()]
    expected = 1 if args.mode == "change" else 0
    expected_value = "9000" if expected else "10"
    if ("before: 10" not in result.stdout.splitlines() or
            "after: " + expected_value not in result.stdout.splitlines()):
        raise RuntimeError("The Java class did not return the expected values")
    if len(events) != expected or int(summary[1]) != expected:
        raise RuntimeError(f"Expected {expected} changes, received {len(events)} reports")
    for event in events:
        if event["kind"] != "class-bytecode-change" or event["subject"] != "bouncer/demo/Score":
            raise RuntimeError("A finding named the wrong event or class")
        fields = event["fields"]
        if fields["event"] != "redefinition-or-retransformation" or int(fields["loader_id"]) <= 0:
            raise RuntimeError("Missing redefinition or classloader identity")
        for label, path in (("previous", original), ("current", replacement)):
            bytecode = path.read_bytes()
            if fields[label + "_hash"] != hashlib.sha256(bytecode).hexdigest():
                raise RuntimeError("Reported hash does not match the real " + label + " class file")
            if int(fields[label + "_size"]) != len(bytecode):
                raise RuntimeError("Reported class size does not match its file")
    print(f"Verified {expected} detection report(s).")
    print("Report: " + str(report))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("demo failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
