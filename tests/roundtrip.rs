#![cfg(not(feature = "deterministic"))]

pub mod support;

use support::{ExpectedOutput, SpawnExt, arcana_cmd, fixtures};

#[test]
fn encrypt_decrypt_default() -> anyhow::Result<()> {
    let plaintext = fixtures::DEFAULT.plaintext()?;
    let encrypt_output = arcana_cmd()
        .arg("encrypt")
        .arg("--password-file")
        .arg(fixtures::DEFAULT.password_file_path())
        .pass_stdin(plaintext.clone())?;
    assert_eq!(encrypt_output.status.code(), Some(0));
    let decrypt_output = arcana_cmd()
        .arg("decrypt")
        .arg("--password-file")
        .arg(fixtures::DEFAULT.password_file_path())
        .pass_stdin(encrypt_output.stdout)?;
    assert_cmd!(decrypt_output, ExpectedOutput::success().stdout(plaintext));
    Ok(())
}
