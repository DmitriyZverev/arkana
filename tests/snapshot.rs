#![cfg(feature = "deterministic")]

pub mod support;

use indoc::indoc;
use std::env::current_dir;
use support::{
    ExpectedOutput, SpawnExt, arcana_cmd, create_temp_dir, create_temp_file, create_temp_file_in,
    fixtures,
};

#[test]
fn encrypt_default() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .pass_stdin(fixtures::DEFAULT.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

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
fn encrypt_long_text() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::LONG_TEXT.password_file_path())
            .pass_stdin(fixtures::LONG_TEXT.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::LONG_TEXT.envelope()?)
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
            Error: kdf.type: unknown variant `argon3`, expected `argon2` at line 2 column 9
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
            Error: cipher.type: unknown variant `ChaCha20Poly1304`, expected `ChaCha20Poly1305` at line 10 column 9
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
fn encrypt_with_input_file() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--input-file")
            .arg(fixtures::DEFAULT.plaintext_file_path())
            .output()?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

#[test]
fn encrypt_with_input_file_short_alias() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("-i")
            .arg(fixtures::DEFAULT.plaintext_file_path())
            .output()?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

#[test]
fn encrypt_with_input_file_long_alias() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--input")
            .arg(fixtures::DEFAULT.plaintext_file_path())
            .output()?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

#[test]
fn encrypt_with_input_file_and_ignore_stdin() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--input-file")
            .arg(fixtures::DEFAULT.plaintext_file_path())
            .pass_stdin("Hello everyone!")?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

#[test]
fn encrypt_with_output_file() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--output-file")
            .arg(output_file.path())
            .pass_stdin(fixtures::DEFAULT.plaintext()?)?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.envelope()?);
    Ok(())
}

#[test]
fn encrypt_with_output_file_short_alias() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("-o")
            .arg(output_file.path())
            .pass_stdin(fixtures::DEFAULT.plaintext()?)?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.envelope()?);
    Ok(())
}

#[test]
fn encrypt_with_output_file_long_alias() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--output")
            .arg(output_file.path())
            .pass_stdin(fixtures::DEFAULT.plaintext()?)?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.envelope()?);
    Ok(())
}

#[test]
fn encrypt_with_input_and_output_files() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--input-file")
            .arg(fixtures::DEFAULT.plaintext_file_path())
            .arg("--output-file")
            .arg(output_file.path())
            .output()?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.envelope()?);
    Ok(())
}

#[test]
fn encrypt_with_cwd_and_relative_input_and_output_files() -> anyhow::Result<()> {
    let current_dir = create_temp_dir()?;
    let password_file = create_temp_file_in(current_dir.path(), &fixtures::DEFAULT.password()?)?;
    let input_file = create_temp_file_in(current_dir.path(), &fixtures::DEFAULT.plaintext()?)?;
    let output_file = create_temp_file_in(current_dir.path(), "")?;
    assert_cmd!(
        arcana_cmd()
            .arg("--cwd")
            .arg(current_dir.path())
            .arg("encrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--input-file")
            .arg(input_file.path())
            .arg("--output-file")
            .arg(output_file.path())
            .output()?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.envelope()?);
    Ok(())
}

#[test]
fn try_encrypt_with_relative_nonexistent_input_file() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
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
fn try_encrypt_with_absolute_nonexistent_input_file() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
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
fn encrypt_with_cipher_type_cha_cha_20_poly_1305_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--cipher-type")
            .arg("ChaCha20Poly1305")
            .pass_stdin(fixtures::DEFAULT.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

#[test]
fn try_encrypt_with_cipher_type_invalid_argument() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--cipher-type")
            .arg("invalid")
            .output()?,
        ExpectedOutput::code(2).stderr(indoc! {"
            error: invalid value 'invalid' for '--cipher-type <CIPHER_TYPE>'
              [possible values: ChaCha20Poly1305]

            For more information, try '--help'.
        "})
    );
    Ok(())
}

#[test]
fn encrypt_with_kdf_type_argon2_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .arg("--kdf-type")
            .arg("argon2")
            .pass_stdin(fixtures::DEFAULT.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

#[test]
fn try_encrypt_with_kdf_type_invalid_argument() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--kdf-type")
            .arg("invalid")
            .output()?,
        ExpectedOutput::code(2).stderr(indoc! {"
            error: invalid value 'invalid' for '--kdf-type <KDF_TYPE>'
              [possible values: argon2]

            For more information, try '--help'.
        "})
    );
    Ok(())
}

#[test]
fn encrypt_with_kdf_argon2_algorithm_argon2i_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2I.password_file_path())
            .arg("--kdf-argon2-algorithm")
            .arg("argon2i")
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2I.plaintext()?)?,
        ExpectedOutput::success()
            .stdout(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2I.envelope()?)
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
fn encrypt_with_kdf_argon2_algorithm_argon2d_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2D.password_file_path())
            .arg("--kdf-argon2-algorithm")
            .arg("argon2d")
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2D.plaintext()?)?,
        ExpectedOutput::success()
            .stdout(fixtures::DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2D.envelope()?)
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
fn try_encrypt_with_kdf_argon2_invalid_algorithm_argument() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--kdf-argon2-algorithm")
            .arg("invalid")
            .output()?,
        ExpectedOutput::code(2).stderr(indoc! {"
            error: invalid value 'invalid' for '--kdf-argon2-algorithm <ALGORITHM>'
              [possible values: argon2id, argon2i, argon2d]

            For more information, try '--help'.
        "})
    );
    Ok(())
}

#[test]
fn encrypt_with_kdf_argon2_version_16_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_VERSION_16.password_file_path())
            .arg("--kdf-argon2-version")
            .arg("16")
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_VERSION_16.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT_KDF_ARGON2_VERSION_16.envelope()?)
    );
    Ok(())
}

#[test]
fn try_encrypt_with_kdf_argon2_version_invalid_argument() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--kdf-argon2-version")
            .arg("17")
            .output()?,
        ExpectedOutput::code(2).stderr(indoc! {"
            error: invalid value '17' for '--kdf-argon2-version <VERSION>'
              [possible values: 16, 19]

            For more information, try '--help'.
        "})
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
fn encrypt_with_kdf_argon2_memory_65536_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_MEMORY_65536.password_file_path())
            .arg("--kdf-argon2-memory")
            .arg("65536")
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_MEMORY_65536.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT_KDF_ARGON2_MEMORY_65536.envelope()?)
    );
    Ok(())
}

#[test]
fn try_encrypt_with_kdf_argon2_memory_invalid_argument() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--kdf-argon2-memory")
            .arg("abc")
            .output()?,
        ExpectedOutput::code(2).stderr(indoc! {"
            error: invalid value 'abc' for '--kdf-argon2-memory <MEMORY>': invalid digit found in string

            For more information, try '--help'.
        "})
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
fn encrypt_with_kdf_argon2_iterations_1_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_ITERATIONS_1.password_file_path())
            .arg("--kdf-argon2-iterations")
            .arg("1")
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_ITERATIONS_1.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT_KDF_ARGON2_ITERATIONS_1.envelope()?)
    );
    Ok(())
}

#[test]
fn try_encrypt_with_kdf_argon2_iterations_invalid_argument() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--kdf-argon2-iterations")
            .arg("abc")
            .output()?,
        ExpectedOutput::code(2).stderr(indoc! {"
            error: invalid value 'abc' for '--kdf-argon2-iterations <ITERATIONS>': invalid digit found in string

            For more information, try '--help'.
        "})
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
fn encrypt_with_kdf_argon2_parallelism_1_argument() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::DEFAULT_KDF_ARGON2_PARALLELISM_1.password_file_path())
            .arg("--kdf-argon2-parallelism")
            .arg("1")
            .pass_stdin(fixtures::DEFAULT_KDF_ARGON2_PARALLELISM_1.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT_KDF_ARGON2_PARALLELISM_1.envelope()?)
    );
    Ok(())
}

#[test]
fn try_encrypt_with_kdf_argon2_parallelism_invalid_argument() -> anyhow::Result<()> {
    let password_file = create_temp_file("test_password_123")?;
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(password_file.path())
            .arg("--kdf-argon2-parallelism")
            .arg("abc")
            .output()?,
        ExpectedOutput::code(2).stderr(indoc! {"
            error: invalid value 'abc' for '--kdf-argon2-parallelism <PARALLELISM>': invalid digit found in string

            For more information, try '--help'.
        "})
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
fn encrypt_with_fastest_kdf_arguments() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--password-file")
            .arg(fixtures::FASTEST.password_file_path())
            .arg("--kdf-argon2-memory")
            .arg("32")
            .arg("--kdf-argon2-iterations")
            .arg("1")
            .arg("--kdf-argon2-parallelism")
            .arg("4")
            .pass_stdin(fixtures::FASTEST.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST.envelope()?)
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
fn encrypt_with_binary_format_default() -> anyhow::Result<()> {
    assert_cmd_binary!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--format")
            .arg("binary")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .pass_stdin(fixtures::DEFAULT.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope_bin()?)
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
fn encrypt_with_yaml_format() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("encrypt")
            .arg("--format")
            .arg("yaml")
            .arg("--password-file")
            .arg(fixtures::DEFAULT.password_file_path())
            .pass_stdin(fixtures::DEFAULT.plaintext()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
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
