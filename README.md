# Security Toolkit

A collection of defensive cybersecurity utilities: file hashing, encryption,
file analysis (entropy, type detection, metadata), password security checks,
network diagnostics, and log analysis.

## Status

🚧 Work in progress — built incrementally, module by module. Currently
implemented: **hashing**, **HMAC**, **encoding (base64/hex)**, and
**AES-256-GCM file encryption**.

## Scope & ethics

This toolkit is for analyzing and securing **systems and files you own or are
authorized to test**. It does not include exploit code, malware, or
unauthorized scanning tools.

## Getting Started

```bash
python3 -m venv venv
source venv/bin/activate       # on Windows Git Bash: source venv/Scripts/activate
pip install -e .
```

### Install globally (WSL / Linux / Mac) — no manual venv activation needed

```bash
sudo apt install pipx -y   # Ubuntu/Debian
pipx ensurepath
pipx install -e .
```

After that, `sectoolkit` works from any directory without activating a venv.

## CLI Usage

### Auto-analyze — just point it at a file

```bash
sectoolkit myfile.txt
```

Runs **every applicable check** against the file automatically (currently:
hashing — more checks will run automatically here as new modules are added,
with zero CLI changes needed). Equivalent to `sectoolkit analyze myfile.txt`.

> **Note:** if a file in your current directory happens to be named exactly
> `hash`, `encrypt`, `decrypt`, or `analyze`, the subcommand takes priority
> over auto-analyzing that file — same behavior as `git`/`npm` when a
> command name collides with a filename. Use `sectoolkit analyze ./hash`
> (with an explicit path) to force analysis in that edge case.

### Hashing

```bash
sectoolkit hash myfile.txt                    # shows md5, sha1, sha256, sha512
sectoolkit hash myfile.txt --algorithm sha256  # just one algorithm
```

### Encrypt / Decrypt files

```bash
sectoolkit encrypt secret.txt secret.enc
# prompts for a password (with confirmation)

sectoolkit decrypt secret.enc secret-restored.txt
# prompts for the password
```

Encryption uses **AES-256-GCM** (authenticated encryption — a wrong password
or a tampered file will fail decryption loudly instead of silently returning
garbage data).

## Library usage

```python
from sectoolkit.hashing import hash_file, hash_file_all, compute_hmac
from sectoolkit.crypto import encrypt_file, decrypt_file
from sectoolkit.encoding import to_base64, from_base64, to_hex, from_hex

hash_file("myfile.txt", "sha256")
encrypt_file("secret.txt", "secret.enc", password="my-password")
```

## Running tests

```bash
pip install -e .
pytest
```

## Project structure

```
sectoolkit/
  hashing.py    # md5/sha1/sha256/sha512, HMAC
  crypto.py     # AES-256-GCM file encryption
  encoding.py   # base64 / hex helpers
  cli.py        # command-line interface
tests/          # pytest test suite
```

## Roadmap

- [x] Hashing (MD5/SHA1/SHA256/SHA512) + HMAC
- [x] Base64/hex encoding utilities
- [x] AES-256-GCM file encryption
- [ ] File analysis: entropy, magic-byte type detection, metadata, strings extraction
- [ ] Password security: strength checker, breach check (HaveIBeenPwned)
- [ ] Network diagnostics: port scanner, DNS lookup, SSL/TLS certificate checker
- [ ] Log analysis: suspicious pattern detection
