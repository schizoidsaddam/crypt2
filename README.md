# znc-crypt2

A drop-in replacement for ZNC's built-in `crypt` module, upgraded from Blowfish-CBC to **AES-256-GCM**.

Same wire format, same commands, same setup. Just better encryption.

## What's different from the original crypt module

| | crypt | crypt2 |
|---|---|---|
| Cipher | Blowfish-CBC | AES-256-GCM |
| IV/Nonce | `time + rand()` (weak) | `RAND_bytes()` (cryptographically random) |
| Authentication | None (malleable) | GCM auth tag (tamper detection) |
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
docker exec -it znc bash

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

## Usage

All commands are identical to the original crypt module, sent to `*crypt2`.

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

Both sides must use the **same key**.

### Other commands

```
/msg *crypt2 ListKeys
/msg *crypt2 DelKey <nick|#channel>
/msg *crypt2 GetNickPrefix
/msg *crypt2 SetNickPrefix <prefix>
```

### Suppress encryption on a single message

Prefix your message with ` `` ` (two backticks) to send plaintext even with a key set.

## Verifying encryption

The ciphertext byte length should always equal `12 (nonce) + len(plaintext) + 16 (tag)`:

```bash
echo "<base64 blob>" | base64 -d | wc -c
```

## Notes

- Keys are stored in plaintext on disk, same as the original crypt module
- Use SSL between ZNC and your IRC client
- Coexists with the original crypt module — both can be loaded simultaneously
