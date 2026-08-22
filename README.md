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

Runs **every applicable check** against the file automatically:

- **hashes** — MD5/SHA1/SHA256/SHA512
- **entropy** — flags likely encrypted/compressed/packed data
- **filetype** — detects the real file type via magic bytes and flags
  extension mismatches (e.g. an `.exe` disguised as `.jpg`)
- **strings** — extracts embedded URLs/IPs from binary content
- **image_metadata** — EXIF data for images, including GPS location if present
- **pdf_metadata** — author, producer, page count, encryption status for PDFs
- **macros** — detects VBA macros in Office documents (`.doc`/`.docm`/`.xls`/etc.)

Each check only runs when it's actually relevant (e.g. `image_metadata` only
applies to image files, `macros` only to Office documents). Equivalent to
`sectoolkit analyze myfile.txt`. As new checks are added to the toolkit,
they show up here automatically — no CLI changes needed.

Add `--json` for machine-readable output:

```bash
sectoolkit analyze myfile.txt --json
```

> **Note:** if a file in your current directory happens to be named exactly
> `hash`, `encrypt`, `decrypt`, or `analyze`, the subcommand takes priority
> over auto-analyzing that file — same behavior as `git`/`npm` when a
> command name collides with a filename. Use `sectoolkit analyze ./hash`
> (with an explicit path) to force analysis in that edge case.

### Full string dump

```bash
sectoolkit strings myfile.bin --min-length 6 --urls-only
```

Prints every matching string (unlike the auto-analyze summary, which only
shows counts and detected URLs/IPs) — closer to the Unix `strings` command.

### Full metadata dump

```bash
sectoolkit metadata photo.jpg
sectoolkit metadata document.pdf
```

Shows the complete metadata dict on its own, without the other checks
running alongside it.

### Crack a hash (dictionary attack)

```bash
sectoolkit crack <hash> wordlists/sample-common-passwords.txt --algorithm sha256
```

Tries every line in the wordlist against the target hash. Reads the
wordlist line-by-line, so it works fine with very large files (millions of
entries) without loading everything into memory.

**Use case:** auditing hashes *you own* — e.g. checking whether a password
hash from your own system/database would fall to a common wordlist, as
part of a security review. This is not for attacking accounts or systems
you don't have explicit authorization to test.

A small bundled wordlist (`wordlists/sample-common-passwords.txt`, ~30
entries from widely-published "most common passwords" lists) is included
for quick testing. For real audits, use a larger list such as
[SecLists](https://github.com/danielmiessler/SecLists) (`rockyou.txt` and
similar) — download it yourself and point `--wordlist` at it; this project
does not bundle large third-party wordlists.

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
- [x] Auto-analyze mode (`sectoolkit <file>`)
- [x] Dictionary-based hash cracking
- [x] File analysis: entropy, magic-byte type detection, strings/URL/IP extraction
- [ ] File metadata extraction (EXIF, PDF metadata, Office macro detection)
- [ ] Password security: strength checker, breach check (HaveIBeenPwned)
- [ ] Network diagnostics: port scanner, DNS lookup, SSL/TLS certificate checker
- [ ] Log analysis: suspicious pattern detection
