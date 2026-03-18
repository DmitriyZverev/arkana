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

### Step 3 — Encryption parameters `Done`

Add flags to override KDF and cipher settings per-invocation.

```shell
arcana encrypt --kdf-type argon2 \
               --kdf-argon2-algorithm argon2id \
               --kdf-argon2-version 19 \
               --kdf-argon2-memory 65536 \
               --kdf-argon2-iterations 3 \
               --kdf-argon2-parallelism 1 \
               --cipher-type ChaCha20Poly1305 < decrypted.txt > encrypted.yml
```

Supported flags:

- `--kdf-type <type>` — select key derivation function (`argon2`)
- `--kdf-argon2-algorithm <algorithm>` — Argon2 algorithm (`argon2id`, `argon2i`, `argon2d`; default: `argon2id`)
- `--kdf-argon2-version <version>` — Argon2 version (`16`, `19`; default: `19`)
- `--kdf-argon2-memory <kib>` — memory in KiB (default: `131072`)
- `--kdf-argon2-iterations <n>` — number of iterations (default: `4`)
- `--kdf-argon2-parallelism <n>` — degree of parallelism (default: `4`)
- `--cipher-type <type>` — select cipher (`ChaCha20Poly1305`)

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

### Step 5 — Named secret storage `Planned`

Introduce a secret registry stored in `$HOME/.arcana/secrets/`. Each encryption
creates a new versioned snapshot of the secret, making it possible to track and
restore previous versions.

The secrets directory can be overridden via `--secrets-dir` or via `config.toml`:

```shell
arcana --secrets-dir /path/to/secrets secret encrypt <secret-name> < ./decrypted.txt
```

```toml
# $HOME/.arcana/config.toml
[secrets]
dir = "/path/to/secrets"
```

`--secrets-dir` takes precedence over the config file value. If neither is set,
`$HOME/.arcana/secrets/` is used.

File naming pattern: `<secret-name>.YYYY_MM_DD_HH_mm_ss_fffffffff_<counter>.yml`

The timestamp in the filename is always in UTC. The latest version is determined by this timestamp
(and counter as a tiebreaker).

**Encrypting a named secret:**

```shell
# From stdin:
arcana secret encrypt <secret-name> < ./decrypted.txt

# From file:
arcana secret encrypt <secret-name> --input ./decrypted.txt
```

Both commands write the encrypted result to:
`$HOME/.arcana/secrets/<secret-name>.YYYY_MM_DD_HH_mm_ss_fffffffff_<counter>.yml`

Each invocation creates a new version; existing versions are never modified. `--output` is not
supported — the destination is always the secrets directory.

**Decrypting a named secret:**

```shell
# To stdout:
arcana secret decrypt <secret-name> > ./decrypted.txt

# To file:
arcana secret decrypt <secret-name> --output ./decrypted.txt
```

**Decrypting a specific version:**

```shell
# To stdout:
arcana secret decrypt <secret-name> --version 2024_03_16_130000_000000000_0001 > ./decrypted.txt

# To file:
arcana secret decrypt <secret-name> --version 2024_03_16_130000_000000000_0001 --output ./decrypted.txt
```

The version identifier matches the filename suffix returned by `arcana secret list-versions <name>`.
Without `--version`, the latest version is used. Exits with an error if the secret or version does not exist.

**Listing all secrets:**

```shell
arcana secret list
```

Outputs the list of secret names stored in `$HOME/.arcana/secrets/`:

```
foo
bar
baz
```

**Listing versions of a secret:**

```shell
arcana secret list-versions <secret-name>
```

Outputs the list of available versions for the specified secret, ordered from oldest to newest:

```
2024_03_16_120000_000000000_0001
2024_03_16_130000_000000000_0001
2024_03_17_090000_000000000_0001
```

**Deleting a secret or a specific version:**

```shell
# Delete all versions of a secret:
arcana secret delete <secret-name>

# Delete a specific version:
arcana secret delete <secret-name> --version 2024_03_16_120000_000000000_0001
```

Without `--version`, all versions are deleted. Any deletion requires interactive confirmation or `--force`
to proceed. Exits with an error if the secret or version does not exist.

**Renaming a secret:**

```shell
arcana secret rename <secret-name> <new-secret-name>
```

Renames all version files of the secret in `$HOME/.arcana/secrets/`.

### Step 6 — Interactive mode (TUI) `Planned`

Run the tool without arguments to launch a terminal user interface (TUI) for browsing,
decrypting, editing, and re-encrypting stored secrets.

```shell
arcana
```
