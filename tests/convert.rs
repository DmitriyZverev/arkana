#![cfg(feature = "deterministic")]

pub mod support;

use support::{ExpectedOutput, SpawnExt, arcana_cmd, create_temp_file, fixtures};

#[test]
fn convert_from_yaml_to_binary() -> anyhow::Result<()> {
    assert_cmd_binary!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("yaml")
            .arg("--to-format")
            .arg("binary")
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope_bin()?)
    );
    Ok(())
}

#[test]
fn convert_from_binary_to_yaml() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("binary")
            .arg("--to-format")
            .arg("yaml")
            .pass_stdin(fixtures::DEFAULT.envelope_bin()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

#[test]
fn convert_from_yaml_to_yaml() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("yaml")
            .arg("--to-format")
            .arg("yaml")
            .pass_stdin(fixtures::DEFAULT.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope()?)
    );
    Ok(())
}

#[test]
fn convert_from_binary_to_binary() -> anyhow::Result<()> {
    assert_cmd_binary!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("binary")
            .arg("--to-format")
            .arg("binary")
            .pass_stdin(fixtures::DEFAULT.envelope_bin()?)?,
        ExpectedOutput::success().stdout(fixtures::DEFAULT.envelope_bin()?)
    );
    Ok(())
}

#[test]
fn convert_from_binary_to_yaml_with_input_and_output_files() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("binary")
            .arg("--to-format")
            .arg("yaml")
            .arg("--input-file")
            .arg(fixtures::DEFAULT.envelope_bin_file_path())
            .arg("--output-file")
            .arg(output_file.path())
            .output()?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.envelope()?);
    Ok(())
}

#[test]
fn convert_from_binary_to_yaml_with_input_and_output_files_short_alias() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("convert")
            .arg("-f")
            .arg("binary")
            .arg("-t")
            .arg("yaml")
            .arg("-i")
            .arg(fixtures::DEFAULT.envelope_bin_file_path())
            .arg("-o")
            .arg(output_file.path())
            .output()?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.envelope()?);
    Ok(())
}

#[test]
fn convert_from_binary_to_yaml_with_input_and_output_files_long_alias() -> anyhow::Result<()> {
    let output_file = create_temp_file("")?;
    assert_cmd!(
        arcana_cmd()
            .arg("convert")
            .arg("--from")
            .arg("binary")
            .arg("--to")
            .arg("yaml")
            .arg("--input")
            .arg(fixtures::DEFAULT.envelope_bin_file_path())
            .arg("--output")
            .arg(output_file.path())
            .output()?,
        ExpectedOutput::success()
    );
    assert_file!(output_file.path(), fixtures::DEFAULT.envelope()?);
    Ok(())
}

#[test]
fn convert_from_yaml_base16_to_yaml_with_encoding_base64() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("yaml")
            .arg("--to-format")
            .arg("yaml")
            .arg("--encoding")
            .arg("base64")
            .pass_stdin(fixtures::FASTEST_BASE16.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST.envelope()?)
    );
    Ok(())
}

#[test]
fn convert_from_binary_to_yaml_with_encoding_base16() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("binary")
            .arg("--to-format")
            .arg("yaml")
            .arg("--encoding")
            .arg("base16")
            .pass_stdin(fixtures::FASTEST_BASE16.envelope_bin()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST_BASE16.envelope()?)
    );
    Ok(())
}

#[test]
fn convert_from_yaml_base16_lowercase_to_yaml_with_encoding_base16() -> anyhow::Result<()> {
    assert_cmd!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("yaml")
            .arg("--to-format")
            .arg("yaml")
            .arg("--encoding")
            .arg("base16")
            .pass_stdin(fixtures::FASTEST_BASE16_LOWERCASE.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST_BASE16.envelope()?)
    );
    Ok(())
}

#[test]
fn convert_from_yaml_base16_to_binary() -> anyhow::Result<()> {
    assert_cmd_binary!(
        arcana_cmd()
            .arg("convert")
            .arg("--from-format")
            .arg("yaml")
            .arg("--to-format")
            .arg("binary")
            .pass_stdin(fixtures::FASTEST_BASE16.envelope()?)?,
        ExpectedOutput::success().stdout(fixtures::FASTEST_BASE16.envelope_bin()?)
    );
    Ok(())
}
