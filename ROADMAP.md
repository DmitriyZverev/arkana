# Roadmap

_This document outlines the planned development stages for `arcana`._

_Each step builds on the previous one, progressively expanding the interface from basic
stdin/stdout piping to a full interactive experience_

## Status legend

| Badge         | Meaning                            |
|---------------|------------------------------------|
| `Done`        | Fully implemented and available    |
| `In progress` | Work has started, not yet complete |
| `Planned`     | Scheduled, work not yet started    |

## Milestones

### Step 1 — Basic stdin/stdout interface `Done`

Encrypt and decrypt data using standard input/output streams. This is the minimal
viable interface and serves as the foundation for all later steps.

```shell
arcana encrypt < decrypted.txt > encrypted.yml
arcana decrypt < encrypted.yml > decrypted.txt
```

### Step 2 — File path arguments `Done`

Add `--input` and `--output` flags as an alternative to stream redirection. Useful when
integrating with scripts or tools that work with file paths directly.

```shell
arcana encrypt --input ./decrypted.txt --output ./encrypted.yml
arcana decrypt --input ./encrypted.yml --output ./decrypted.txt
```

### Step 3 — Encryption parameters `Planned`

Add flags to override KDF and cipher settings per-invocation.

```shell
arcana encrypt --kdf-type argon2 \
               --kdf-argon2-algorithm argon2id \
               --kdf-argon2-memory 65536 \
               --kdf-argon2-iterations 3 \
               --kdf-argon2-parallelism 1 \
               --cipher-type chacha20poly1305 < decrypted.txt > encrypted.yml
```

Supported flags:

- `--kdf-type <type>` — select key derivation function (e.g. `argon2`)
- `--kdf-<type>-<parameter> <value>` — set a KDF-specific parameter (e.g. `--kdf-argon2-memory 65536`)
- `--cipher-type <type>` — select cipher (e.g. `chacha20poly1305`)

### Step 4 — Configuration file `Planned`

Add support for a configuration file at `$HOME/.arcana/config.toml` for setting default
encryption parameters:

```toml
# $HOME/.arcana/config.toml
[kdf]
type = "argon2"

[kdf.argon2]
algorithm = "argon2id"
memory = 65536
iterations = 3
parallelism = 1

[cipher]
type = "chacha20poly1305"
```

The default config path can be overridden with `--config`:

```shell
arcana --config /path/to/config.toml encrypt < decrypted.txt > encrypted.yml
```

CLI flags (Step 3) take precedence over config file values.

### Step 5 — Named document storage `Planned`

Introduce a document registry stored in `$HOME/.arcana/documents/`. Each encryption
creates a new versioned snapshot of the document, making it possible to track and
restore previous versions.

The documents directory can be overridden via `--documents-dir` or via `config.toml`:

```shell
arcana --documents-dir /path/to/documents encrypt --document document-name < ./decrypted.txt
```

```toml
# $HOME/.arcana/config.toml
[documents]
dir = "/path/to/documents"
```

`--documents-dir` takes precedence over the config file value. If neither is set,
`$HOME/.arcana/documents/` is used.

File naming pattern: `<document-name>.YYYY_MM_DD_HH_mm_ss_fffffffff_<counter>.yml`

**Encrypting a named document:**

```shell
# From stdin:
arcana encrypt --document document-name < ./decrypted.txt

# From file:
arcana encrypt --document document-name --input ./decrypted.txt
```

Both commands write the encrypted result to:
`$HOME/.arcana/documents/document-name.YYYY_MM_DD_HH_mm_ss_fffffffff_0001.yml`

**Decrypting a named document:**

```shell
# To stdout:
arcana decrypt --document document-name > decrypted.txt

# To file:
arcana decrypt --document document-name --output ./decrypted.txt
```

Decryption automatically resolves to the latest version of the document found in
`$HOME/.arcana/documents/`.

### Step 6 — Interactive mode (TUI) `Planned`

Run the tool without arguments to launch a terminal user interface (TUI) for browsing,
decrypting, editing, and re-encrypting stored documents.

```shell
arcana
```
