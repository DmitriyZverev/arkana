#![cfg(feature = "deterministic")]

pub mod support;

use indoc::indoc;
use std::env::current_dir;
use support::{
    ExpectedOutput, SpawnExt, arcana_cmd, create_temp_dir, create_temp_file, create_temp_file_in,
    fixtures,
};

#[test]
fn decrypt_default() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_long_text() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::LONG_TEXT.password_file_path())
            .pass_stdin(fixtures::LONG_TEXT.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::LONG_TEXT.plaintext()?)
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_password() -> anyhow::Result<()> {
    let password_file = create_temp_file("invalid_password")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decryption failed
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_kdf_type() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon3
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: kdf.type: unknown variant `argon3`, expected `argon2` at line 3 column 9
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_kdf_algorithm() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: unknown variant `argon2`, expected one of `argon2i`, `argon2d`, `argon2id`
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_kdf_memory() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131071
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decryption failed
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_kdf_iterations() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 1
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decryption failed
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_kdf_parallelism() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 1
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decryption failed
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_cipher_type() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1304
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: cipher.type: unknown variant `ChaCha20Poly1304`, expected `ChaCha20Poly1305` at line 11 column 9
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_salt() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: CxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decryption failed
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_nonce() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: GgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decryption failed
        "})
    );
    Ok(())
}

#[test]
fn decrypt_with_input_file() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--input-file")
            .arg(fixtures::DEFAULT.envelope_file_path())
            .output()?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_input_file_short_alias() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("-i")
            .arg(fixtures::DEFAULT.envelope_file_path())
            .output()?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_input_file_long_alias() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--input")
            .arg(fixtures::DEFAULT.envelope_file_path())
            .output()?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_input_file_and_ignore_stdin() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--input-file")
            .arg(fixtures::DEFAULT.envelope_file_path())
            .pass_stdin("Ignored input")?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_output_file() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--output-file")
            .arg(output_file.path())
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.plaintext()?);
    Ok(())
}

#[test]
fn decrypt_with_output_file_short_alias() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("-o")
            .arg(output_file.path())
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.plaintext()?);
    Ok(())
}

#[test]
fn decrypt_with_output_file_long_alias() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--output")
            .arg(output_file.path())
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.plaintext()?);
    Ok(())
}

#[test]
fn decrypt_with_input_and_output_files() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--input-file")
            .arg(fixtures::DEFAULT.envelope_file_path())
            .arg("--output-file")
            .arg(output_file.path())
            .output()?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.plaintext()?);
    Ok(())
}

#[test]
fn decrypt_with_cwd_and_relative_input_and_output_files() -> anyhow::Result<()> {
    let current_dir = create_temp_dir()?;
    let password_file = create_temp_file_in(current_dir.path(), &fixtures::DEFAULT.password()?)?;
    let input_file = create_temp_file_in(current_dir.path(), &fixtures::DEFAULT.envelope()?)?;
    let output_file = create_temp_file_in(current_dir.path(), "")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--input-file")
            .arg(input_file.path())
            .arg("--output-file")
            .arg(output_file.path())
            .output()?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.plaintext()?);
    Ok(())
}

#[test]
fn try_decrypt_with_relative_nonexistent_input_file() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--input-file")
            .arg("./nonexistent/path/input.txt")
            .output()?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Failed to read input file: \"nonexistent/path/input.txt\"

            Caused by:
                No such file or directory (os error 2)
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_absolute_nonexistent_input_file() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--input-file")
            .arg(current_dir()?.join("nonexistent/path/input.txt"))
            .output()?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Failed to read input file: \"nonexistent/path/input.txt\"

            Caused by:
                No such file or directory (os error 2)
        "})
    );
    Ok(())
}

#[test]
fn decrypt_with_kdf_argon2_algorithm_argon2i_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2I.password_file_path())
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2I.envelope()?)?,
        ExpectedOutput::success()
            .stdout(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2I.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_kdf_argon2_algorithm_argon2d_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2D.password_file_path())
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2D.envelope()?)?,
        ExpectedOutput::success()
            .stdout(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2D.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_kdf_argon2_version_16_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_VERSION_16.password_file_path())
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_VERSION_16.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT_KDF_ARGON2_VERSION_16.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_kdf_argon2_memory_65536_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_MEMORY_65536.password_file_path())
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_MEMORY_65536.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT_KDF_ARGON2_MEMORY_65536.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_kdf_argon2_iterations_1_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_ITERATIONS_1.password_file_path())
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_ITERATIONS_1.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT_KDF_ARGON2_ITERATIONS_1.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_kdf_argon2_parallelism_1_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_PARALLELISM_1.password_file_path())
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_PARALLELISM_1.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT_KDF_ARGON2_PARALLELISM_1.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_fastest_kdf_arguments() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::FASTEST.password_file_path())
            .pass_stdin(fixtures::FASTEST.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_binary_format() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--format")
            .arg("binary")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .pass_stdin(fixtures::DEFAULT.envelope_bin()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_yaml_format() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--format")
            .arg("yaml")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.plaintext()?)
    );
    Ok(())
}

#[test]
fn try_decrypt_yaml_envelope_with_binary_format() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--format")
            .arg("binary")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::failure().stderr(indoc! {r#"
            Error: Semantic(None, "invalid type: string, expected map")
        "#})
    );
    Ok(())
}

#[test]
fn try_decrypt_binary_envelope_with_yaml_format() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--format")
            .arg("yaml")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .pass_stdin(fixtures::DEFAULT.envelope_bin()?)?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: invalid leading UTF-8 octet
        "})
    );
    Ok(())
}

#[test]
fn decrypt_with_encoding_base16() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::FASTEST_BASE16.password_file_path())
            .pass_stdin(fixtures::FASTEST_BASE16.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST_BASE16.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_encoding_base16_lowercase() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::FASTEST_BASE16_LOWERCASE.password_file_path())
            .pass_stdin(fixtures::FASTEST_BASE16_LOWERCASE.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST_BASE16_LOWERCASE.plaintext()?)
    );
    Ok(())
}

#[test]
fn decrypt_with_encoding_base32() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(fixtures::FASTEST_BASE32.password_file_path())
            .pass_stdin(fixtures::FASTEST_BASE32.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST_BASE32.plaintext()?)
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_salt_length() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGw==
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decoding error: Invalid length: expected 32, actual 31
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_nonce_length() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgo=
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decoding error: Invalid length: expected 12, actual 11
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_tag_length() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base64
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+Z
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: Decoding error: Invalid length: expected 16, actual 15
        "})
    );
    Ok(())
}

#[test]
fn try_decrypt_with_invalid_encoding_value() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .pass_stdin(indoc! {"
                encoding: base58
                kdf:
                  type: argon2
                  algorithm: argon2id
                  version: 19
                  memory: 131072
                  iterations: 4
                  parallelism: 4
                  salt: GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxs=
                cipher:
                  type: ChaCha20Poly1305
                  nonce: CgoKCgoKCgoKCgoK
                  tag: h1yYEdQ5IHcvz3UL7W+ZHQ==
                  ciphertext: RmuSIEhbLyex+iTU
            "})?,
        ExpectedOutput::failure().stderr(indoc! {"
            Error: encoding: unknown variant `base58`, expected one of `base16`, `base32`, `base64` at line 1 column 11
        "})
    );
    Ok(())
}
