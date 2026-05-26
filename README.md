# znc-crypt2

A drop-in replacement for ZNC's built-in `crypt` module, upgraded from Blowfish-CBC to **AES-256-GCM** with HKDF key derivation and AAD target binding.

Same wire format, same commands, same setup. Just better encryption.

## What's different from the original crypt module

| | crypt | crypt2 |
|---|---|---|
| Cipher | Blowfish-CBC | AES-256-GCM |
| IV/Nonce | `time + rand()` (weak) | `RAND_bytes()` (cryptographically random) |
| Authentication | None (malleable) | GCM auth tag (tamper detection) |
| Key derivation | Raw key bytes | HKDF-SHA256 |
| Target binding | None | AAD prevents message transplantation across targets |
| Wire format | `+OK *<base64>` | `+OK *<base64>` (identical) |
| Commands | unchanged | unchanged |

## Requirements

- ZNC 1.8+
- OpenSSL 3.x
- Both sides must run crypt2 — this is **not** compatible with the original crypt module or Mircryption

## Installation

### Building inside a Docker container (linuxserver/znc)

```bash
# Copy source into your ZNC data directory
sudo cp crypt2.cpp /srv/znc/data/modules/

# Shell into the container
docker exec -it znc sh

# Inside the container — install build tools (Alpine-based image)
apk add znc-dev build-base

# Build the module
# Note: znc-buildmod writes the .so to the current directory (/ by default)
znc-buildmod /config/modules/crypt2.cpp

# Copy the compiled .so to the modules directory
cp /crypt2.so /config/modules/

# Exit the container
exit
```

### Building on a bare-metal ZNC install

```bash
znc-buildmod crypt2.cpp
mv crypt2.so ~/.znc/modules/
```

### Loading the module

From your IRC client:
```
/msg *status LoadModule crypt2
```

If you're replacing a previous version of crypt2, unload it first:
```
/msg *status UnloadModule crypt2
/msg *status LoadModule crypt2
```

## Usage

All commands are sent to `*crypt2`.

### Key exchange (automatic, recommended)

Initiate a DH1080 key exchange with another crypt2 user:
```
/msg *crypt2 KeyX <nick>
```

### Manual key setup

Generate a key:
```bash
openssl rand -base64 32
```

Set it on both sides:
```
/msg *crypt2 SetKey <nick|#channel> <key>
```

Both sides must use the **same key**. If you previously had crypt2 loaded with an older key, you must set a new key — HKDF derives differently from the same input compared to the old version.

### Other commands

```
/msg *crypt2 ListKeys
/msg *crypt2 DelKey <nick|#channel>
/msg *crypt2 GetNickPrefix
/msg *crypt2 SetNickPrefix <prefix>
```

### Suppress encryption on a single message

Prefix your message with ` `` ` (two backticks) to send plaintext even with a key set.

## Security notes

- **AAD (Associated Authenticated Data):** ciphertext is cryptographically bound to the target nick or channel. A message encrypted for `#channel` cannot be successfully decrypted as a private message or replayed to a different channel, even with the same key.
- **HKDF:** the same raw key produces a different derived key per target, providing additional key separation beyond AAD.
- **Tamper detection:** any modification to the ciphertext, nonce, or GCM tag causes decryption to fail with `(decryption failed - wrong key or tampered message)`.
- **Keys are stored in plaintext on disk**, same as the original crypt module. Use SSL between ZNC and your IRC client.
- DH1080 key exchange is supported but is unauthenticated (no MITM protection). For higher security, use manual `SetKey` with an out-of-band key exchange.

## Verifying encryption

The ciphertext byte length should always equal `12 (nonce) + len(plaintext) + 16 (tag)`:

```bash
echo "<base64 blob>" | base64 -d | wc -c
```
