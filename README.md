# Strawberry Secret Vault

A simple .NET console app that:
- Encrypts a user-provided message using AES-256-GCM + PBKDF2 (SHA-512) key derivation.
- Stores each encrypted message and its (base64) password in a timestamped folder under `data/`.
- Provides a hidden decryption mode unlocked by a secret phrase (stored base64 in configuration).

> Educational / demo purposes only. Do **not** use this exact pattern (especially storing passwords) in production.

---
## Features
- AES-256-GCM authenticated encryption (random per-message salt + nonce; 128-bit tag).
- PBKDF2 (SHA-512) with configurable iteration count.
- Versioned binary container format (`secret.bin`) for forward compatibility.
- Hidden decrypt menu triggered by a secret phrase (not shown in UI).
- Configurable via `appsettings.json`.
- Output artifacts ignored from git (`data/**`).

---
## Project Structure
```
appsettings.json         # Global encryption + app config
Program.cs               # Main application logic
strawberry-secret-exercise.csproj
/ data/                  # (git-ignored) timestamped encrypted message folders
```

Each run (encryption) creates: `data/<UTC_yyyyMMdd_HHmmssfff>/secret.bin` and `password.b64`.

---
## Build & Run
Requires .NET 9 SDK.

```powershell
# Build
dotnet build .\strawberry-secret-exercise.csproj

# Run (interactive)
dotnet run --project .\strawberry-secret-exercise.csproj
```

Main menu shows only:
```
=== Strawberry Secret Vault ===
1) Encrypt new message
Select option (1) or enter secret phrase:
```
To decrypt you must enter the secret phrase instead of a menu number (see below).

---
## Configuration (`appsettings.json`)
```json
{
  "Encryption": {
    "Algorithm": "AES-256-GCM",
    "Kdf": "PBKDF2",
    "Iterations": 150000,
    "SaltSizeBytes": 32,
    "NonceSizeBytes": 12,
    "PasswordFile": "password.b64",
    "CipherTextFile": "secret.bin",
    "DataRoot": "data",
    "SecretPhraseB64": "a3VyZGlza2Fyw6R2ZW4=",
    "ConfigNote": "Adjust iterations for security/performance tradeoff."
  }
}
```
Key fields:
- `Iterations`: PBKDF2 iterations (raise for more resistance to brute force; test performance).
- `SaltSizeBytes`: Random salt length per message.
- `NonceSizeBytes`: AES-GCM nonce length (12 recommended).
- `SecretPhraseB64`: Base64 of the hidden decrypt trigger phrase.
- `PasswordFile`: Name of base64 password file saved per message (demo only!).
- `CipherTextFile`: Encrypted payload container.

To change the secret phrase:
1. Choose a phrase (UTF-8).  
2. Base64 encode it. (PowerShell example: `[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('new phrase'))` )  
3. Replace `SecretPhraseB64` value and re-run.

---
## Hidden Decrypt Flow
1. Run the app.
2. At prompt enter the (plain) secret phrase (not its Base64 form).
3. A list of folders is shown; pick one to decrypt.
4. The app auto-loads `password.b64`, decodes it, derives the key, and prints the plaintext.

If you share with others for a challenge:
- Send only the selected `data/<folder>` directory (containing `secret.bin`).
- Send the password out-of-band (preferred) OR include `password.b64` if you want them to succeed easily.
- Provide the secret phrase separately so they can access the decrypt menu.

---
## File Format: `secret.bin`
Layout (all big endian for integers):
```
[4]  Magic bytes      = 'SERC' (0x53 0x45 0x52 0x43)
[1]  Version          = 0x01
[1]  Salt length (S)
[1]  Nonce length (N)
[1]  Tag length (T)
[4]  Iteration count (I)
[S]  Salt
[N]  Nonce
[T]  Tag (GCM authentication tag)
[..] Ciphertext (len = remaining bytes)
```
Key derivation: `key = PBKDF2(password, salt, I, SHA512, 32 bytes)`.
Encryption: `AES-256-GCM(nonce, plaintext) -> (ciphertext, tag)`.

---
## Security Notes / Caveats
- Storing the password (even base64) beside the ciphertext defeats confidentiality—keep it only for demonstrations.
- Base64 is not encryption; it’s encoding. Anyone with the files can recover the password.
- Increase `Iterations` over time as hardware improves.
- Consider replacing PBKDF2 with Argon2 or scrypt for stronger memory-hard resistance in real use.
- Nonce is random per message; do NOT reuse `(key, nonce)` pairs.
- Secret phrase obfuscation (Base64) is minimal; determined users can recover it from config.

---
## Extending / Ideas
- Add a mode to prompt for password (don’t store it).
- Add optional Argon2 (via third-party library) with configurable memory cost.
- Support signing / detached MAC for tamper evidence separate from encryption.
- Implement a decrypt-only minimal tool.
- Add compression before encryption.

---
## Quick Decrypt Without App (Pseudocode)
```
Read header -> get S,N,T,I
Read salt, nonce, tag, ciphertext
key = PBKDF2(password, salt, I, SHA512, 32)
AES-GCM Decrypt(nonce, ciphertext, tag) -> plaintext
```

---
## Disclaimer
This repository is for learning. **Do not** treat it as production-grade secure storage. Remove password persistence and strengthen secret management before any real deployment.

---
Happy experimenting!
