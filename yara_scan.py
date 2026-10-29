#!/usr/bin/env python3

import hashlib
import os
import subprocess
import sys
from pathlib import Path

RULES = "/opt/jenkins-security/yara/github-threats.yar"
REPORT = "yara-findings.txt"

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    ".venv",
    "__pycache__"
}

def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def scan_file(path):
    result = subprocess.run(
        ["yara", "-s", RULES, str(path)],
        capture_output=True,
        text=True
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"YARA execution failed for {path}: "
            f"{result.stderr.strip()}"
        )

    return result.stdout.strip()


def main():
    findings = []
    scanned = 0
    errors = []

    root = Path.cwd()

    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for filename in files:
            path = Path(directory) / filename

            if path.name == REPORT:
                continue

            if not path.is_file() or path.is_symlink():
                continue

            scanned += 1

            try:
                result = scan_file(path)

                if result:
                    findings.append({
                        "file": str(path.relative_to(root)),
                        "full_path": str(path),
                        "sha256": sha256_file(path),
                        "matches": result
                    })

            except Exception as e:
                errors.append(f"{path}: {e}")

    with open(REPORT, "w") as report:

        report.write("YARA SECURITY SCAN REPORT\n")
        report.write("=" * 60 + "\n")

        report.write(f"Files Scanned: {scanned}\n")
        report.write(f"Files with Matches: {len(findings)}\n")
        report.write(f"Scan Errors: {len(errors)}\n\n")

        for index, finding in enumerate(findings, 1):

            report.write(f"DETECTION #{index}\n")
            report.write("-" * 60 + "\n")

            report.write(f"File: {finding['file']}\n")
            report.write(f"Full Path: {finding['full_path']}\n")
            report.write(f"SHA256: {finding['sha256']}\n")

            report.write("Matched Rules and Strings:\n")
            report.write(finding["matches"] + "\n\n")

        if errors:
            report.write("SCAN ERRORS\n")
            report.write("-" * 60 + "\n")
            report.write("\n".join(errors) + "\n")

    print(open(REPORT).read())

    if findings or errors:
        print("SECURITY GATE FAILED")
        sys.exit(1)

    print("SECURITY GATE PASSED")


if __name__ == "__main__":
    main()
