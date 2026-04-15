mod cli;
mod crypto;
mod envelope;
mod password;

use crate::cli::{CliArgs, Format, SubCommand};
use crate::crypto::{EncryptParams, decrypt, encrypt};
use crate::password::read_password;
use anyhow::Context;
use clap::Parser;
use path_absolutize::Absolutize;
use pathdiff::diff_paths;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

fn read_input(path: Option<PathBuf>, cwd: &PathBuf) -> anyhow::Result<Vec<u8>> {
    match path {
        Some(p) => fs::read(&p).with_context(|| {
            format!(
                "Failed to read input file: \"{}\"",
                diff_paths(&p, cwd).as_deref().unwrap_or(&p).display()
            )
        }),
        None => {
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            Ok(data)
        }
    }
}

fn write_output(data: &[u8], path: Option<PathBuf>, cwd: &PathBuf) -> anyhow::Result<()> {
    match path {
        Some(p) => fs::write(&p, data).with_context(|| {
            format!(
                "Failed to write output file: \"{}\"",
                diff_paths(&p, cwd).as_deref().unwrap_or(&p).display()
            )
        }),
        None => Ok(std::io::stdout().write_all(data)?),
    }
}

fn resolve_path(
    base: &std::path::Path,
    path: Option<PathBuf>,
) -> Result<Option<PathBuf>, std::io::Error> {
    match path {
        Some(p) => Ok(Some(p.absolutize_from(base)?.to_path_buf())),
        None => Ok(None),
    }
}

fn main() -> anyhow::Result<()> {
    let cli_args = CliArgs::parse();
    let cwd = match cli_args.cwd {
        Some(path) => path,
        None => std::env::current_dir()?,
    };
    match cli_args.command {
        Some(SubCommand::Encrypt {
            io,
            encoding,
            kdf,
            cipher,
        }) => {
            let input_file = resolve_path(&cwd, io.input_file)?;
            let output_file = resolve_path(&cwd, io.output_file)?;
            let password_file = resolve_path(&cwd, io.password_file)?;
            let encrypt_params = EncryptParams {
                data: read_input(input_file, &cwd)?,
                password: read_password(password_file)?,
                kdf: kdf.into(),
                cipher: cipher.into(),
            };
            let envelope = encrypt(encrypt_params)?;
            let output = match io.format {
                Format::Yaml => {
                    let text_envelope = envelope::text::Envelope::encode(envelope, encoding.into());
                    serde_yaml::to_string(&text_envelope)?.into_bytes()
                }
                Format::Binary => {
                    let mut binary_data = Vec::new();
                    ciborium::into_writer(&envelope, &mut binary_data)?;
                    binary_data
                }
            };
            write_output(&output, output_file, &cwd)?;
        }
        Some(SubCommand::Decrypt { io }) => {
            let input_file = resolve_path(&cwd, io.input_file)?;
            let output_file = resolve_path(&cwd, io.output_file)?;
            let password_file = resolve_path(&cwd, io.password_file)?;
            let data = read_input(input_file, &cwd)?;
            let envelope: envelope::Envelope = match io.format {
                Format::Yaml => {
                    serde_yaml::from_slice::<envelope::text::Envelope>(&data)?.try_into()?
                }
                Format::Binary => ciborium::from_reader(data.as_slice())?,
            };
            let decrypted_text = decrypt(envelope, &read_password(password_file)?)?;
            write_output(&decrypted_text, output_file, &cwd)?;
        }
        Some(SubCommand::Convert {
            from_format,
            to_format,
            encoding,
            input_file,
            output_file,
        }) => {
            let input_file = resolve_path(&cwd, input_file)?;
            let output_file = resolve_path(&cwd, output_file)?;
            let data = read_input(input_file, &cwd)?;
            let envelope: envelope::Envelope = match from_format {
                Format::Yaml => {
                    serde_yaml::from_slice::<envelope::text::Envelope>(&data)?.try_into()?
                }
                Format::Binary => ciborium::from_reader(data.as_slice())?,
            };
            let output = match to_format {
                Format::Yaml => {
                    let text_envelope = envelope::text::Envelope::encode(envelope, encoding.into());
                    serde_yaml::to_string(&text_envelope)?.into_bytes()
                }
                Format::Binary => {
                    let mut binary_data = Vec::new();
                    ciborium::into_writer(&envelope, &mut binary_data)?;
                    binary_data
                }
            };
            write_output(&output, output_file, &cwd)?;
        }
        None => {
            return Err(anyhow::anyhow!("No command specified"));
        }
    }
    Ok(())
}
