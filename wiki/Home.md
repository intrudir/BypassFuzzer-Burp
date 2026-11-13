# BypassFuzzer Wiki

The wiki contains mode workflows and technique explanations. The README is the
entry point for installation, builds and current UI usage.

- [Coverage Sweep Mode](Coverage-Sweep-Mode)
- [AuthZ Bypass Playbooks](AuthZ-Bypass-Playbooks)
- [URL Validation Playbooks](URL-Validation-Playbooks)
- [IDOR / BOLA Playbooks](IDOR-BOLA-Playbooks)

Current command syntax, catalog selection and execution contracts live in the
main repository:

- [CLI reference](https://github.com/intrudir/BypassFuzzer-Burp/blob/main/docs/CLI.md)
- [Shared bypass catalog and calibration](https://github.com/intrudir/BypassFuzzer-Burp/blob/main/docs/bypass-playbooks.md)
- [Pause, edit and resume](https://github.com/intrudir/BypassFuzzer-Burp/blob/main/docs/LIVE-RUN-CONTROL.md)
- [Shared engine and contributor boundaries](https://github.com/intrudir/BypassFuzzer-Burp/blob/main/docs/SCAN-ENGINE.md)

The repository's `wiki/` directory is the source for these pages. Publishing it
is a separate operation through `scripts/publish-wiki.sh`.
