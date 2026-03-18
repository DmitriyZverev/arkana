# Arcana

_A modern CLI tool for password-based encryption with human-readable output._

## Status

> [!IMPORTANT]
> This project is in early development, and the API may change at any time.
> Not recommended for production use.

## Features

- **Strong Encryption**: `ChaCha20-Poly1305` authenticated encryption
- **Secure Key Derivation**: `Argon2id` with configurable parameters
- **Flexible I/O**: Stdin/stdout by default, with optional `--input-file` / `--output-file` flags
- **Configurable Encryption Parameters**: Override KDF and cipher settings per-invocation via CLI flags
- **YAML Output Format**: Human-readable encrypted containers

## Usage

### Encrypt Data

```bash
# Read from stdin, write to stdout
echo "secret message" | arcana encrypt > encrypted.yml

# Read from file, write to stdout
arcana encrypt --input-file secret.txt > encrypted.yml

# Read from stdin, write to file
echo "secret message" | arcana encrypt --output-file encrypted.yml

# Read from file, write to file
arcana encrypt --input-file secret.txt --output-file encrypted.yml
```

### Decrypt Data

```bash
# Read from stdin, write to stdout
arcana decrypt < encrypted.yml > decrypted.txt

# Read from file, write to stdout
arcana decrypt --input-file encrypted.yml > decrypted.txt

# Read from stdin, write to file
arcana decrypt --output-file decrypted.txt < encrypted.yml

# Read from file, write to file
arcana decrypt --input-file encrypted.yml --output-file decrypted.txt
```

> [!NOTE]
> When `--input-file` is provided, stdin is ignored. When `--output-file` is provided, nothing is written to stdout.

### Encryption Parameters

Use `--kdf-*` and `--cipher-type` flags to override encryption parameters. When omitted, secure defaults are used.

```bash
# Encrypt with a custom Argon2 algorithm
arcana encrypt --kdf-argon2-algorithm argon2i --input-file decrypted.txt

# Encrypt with reduced memory usage for faster key derivation
arcana encrypt --kdf-argon2-memory 65536 --input-file decrypted.txt

# Encrypt with all parameters explicitly specified
arcana encrypt \
  --kdf-type argon2 \
  --kdf-argon2-algorithm argon2id \
  --kdf-argon2-version 19 \
  --kdf-argon2-memory 131072 \
  --kdf-argon2-iterations 4 \
  --kdf-argon2-parallelism 4 \
  --cipher-type ChaCha20Poly1305 \
  --input-file decrypted.txt
```

> [!NOTE]
> Encryption parameters are stored in the container and are used automatically during decryption — no flags are needed
> on `arcana decrypt`.

### Override Working Directory

Use the `--cwd` global flag to set the working directory for resolving all relative file paths:

```bash
# Without --cwd, relative paths are resolved against the current working directory
cd /path/to/dir && arcana encrypt --input-file secret.txt --output-file encrypted.yml

# With --cwd, relative paths are resolved against the specified directory
arcana --cwd /path/to/dir encrypt --input-file secret.txt --output-file encrypted.yml
```

## Encrypted Container Format

The encrypted data is stored in a human-readable YAML format that describes all necessary settings for decryption:

```yaml
kdf:
  type: argon2
  algorithm: argon2id
  version: 19
  memory: 131072
  iterations: 4
  parallelism: 4
cipher:
  type: ChaCha20Poly1305
salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
nonce: CgoKCgoKCgoKCgoK
ciphertext: |-
  QmGMKUpbMTiw4y3VNcyRczjoWe3tDsafehFLdnVsACiAdBg4AH91oORjkONGmEN+
  QpRkityFXVFY/FdiCmC6+0xo5TZwuhY55fKfiVw1oVUUbQvUu54uiZWc8iibZ+H9
  80N4XRKNKiFvUA7DbG3rMO+RomI4hyGM0l5S3E5LZEALkoV6ivpWeKHyOsCuef+J
  LmFJ

```

## Security Parameters

- **Argon2id**: Memory-hard key derivation (128 MiB, 4 iterations, parallelism 4)
- **ChaCha20-Poly1305**: Authenticated encryption with 256-bit keys
- **Salt**: 256-bit random salt per encryption
- **Nonce**: 96-bit random nonce per encryption
