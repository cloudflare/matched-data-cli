#![warn(rust_2018_idioms)]

mod matched_data;

use crate::matched_data::generate_key_pair;
use clap::{ArgEnum, Clap};
use hpke::kex::Serializable;
use serde::{Deserialize, Serialize};
use std::io::{stdin, stdout, Write};
use std::{fs, str};

#[derive(Clap)]
#[clap(author, version)]
struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(ArgEnum)]
enum KeyPairOutputFormat {
    Json,
}

#[derive(Clap)]
struct GenerateKeyPairOptions {
    #[clap(
        arg_enum,
        short,
        long,
        value_name = "format",
        about = "Output format of key pair",
        default_value = "json"
    )]
    output_format: KeyPairOutputFormat,
}

#[derive(ArgEnum)]
enum DecryptOutputFormat {
    Raw,
    Utf8Lossy,
}

#[derive(Clap)]
struct DecryptOptions {
    #[clap(about = "File containing the base64 encoded encrypted matched data")]
    matched_data_filename: String,

    #[clap(
        short = 'k',
        long,
        about = "File containing the base64 encoded private key"
    )]
    private_key_filename: String,

    #[clap(
        arg_enum,
        short,
        long,
        value_name = "format",
        about = "Output format of matched data",
        default_value = "utf8-lossy"
    )]
    output_format: DecryptOutputFormat,
}

#[derive(Clap)]
enum Command {
    /// Generates a public-private key pair
    GenerateKeyPair(GenerateKeyPairOptions),

    /// Decrypts data
    Decrypt(DecryptOptions),
}

#[derive(Serialize, Deserialize)]
struct KeyPair {
    private_key: String,
    public_key: String,
}

fn run(options: Options) -> Result<(), String> {
    match options.command {
        Command::GenerateKeyPair(command) => {
            // Generate key pair
            let (private_key, public_key) = generate_key_pair();

            let key_pair = KeyPair {
                private_key: radix64::STD.encode(&private_key.to_bytes()),
                public_key: radix64::STD.encode(&public_key.to_bytes()),
            };

            match command.output_format {
                KeyPairOutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&key_pair).expect("Failed to output key pair")
                    );
                }
            }
        }
        Command::Decrypt(command) => {
            // Validate and construct private key from input
            let private_key_base64 = fs::read_to_string(command.private_key_filename)
                .map_err(|_| "Failed to read private key from file")?;

            let private_key_bytes = radix64::STD
                .decode(&private_key_base64.trim_end())
                .map_err(|_| "Provided private key is not base64 encoded")?;

            // Validate and construct matched data from input
            let matched_data_base64 = if command.matched_data_filename == "-" {
                let mut buffer = String::new();
                stdin()
                    .read_line(&mut buffer)
                    .map_err(|_| "Failed to read matched data from stdin")?;
                buffer
            } else {
                fs::read_to_string(command.matched_data_filename)
                    .map_err(|_| "Failed to read matched data from file")?
            };
            let encrypted_matched_data_bytes = radix64::STD
                .decode(&matched_data_base64.trim_end())
                .map_err(|_| "Provided matched data is not base64 encoded")?;

            macro_rules! decrypt {
                ($modname:ident) => {{
                    use $modname::{
                        decrypt_data, deserialize_encrypted_data, get_private_key_from_bytes,
                    };

                    let private_key = get_private_key_from_bytes(&private_key_bytes)
                        .map_err(|_| "Provided private key is invalid")?;

                    let encrypted_matched_data =
                        deserialize_encrypted_data(&encrypted_matched_data_bytes)
                            .map_err(|_| "Provided matched data is invalid")?;

                    // Decrypt matched data
                    decrypt_data(&encrypted_matched_data, &private_key)
                        .map_err(|_| "Failed to decrypt matched data")?
                }};
            }

            // Get encryption version
            let encryption_format_version = encrypted_matched_data_bytes[0];
            let matched_data = match encryption_format_version {
                3 => decrypt!(matched_data),
                _ => {
                    let available_versions = "'3'";

                    return Err(format!(
                        "Encryption format not supported, expected {}, got '{}'",
                        available_versions, encryption_format_version
                    ));
                }
            };

            match command.output_format {
                DecryptOutputFormat::Raw => {
                    let mut out = stdout();
                    out.write_all(&matched_data)
                        .map_err(|_| "Failed to output matched data")?;
                    out.flush().expect("Failed to flush stdout");
                }
                DecryptOutputFormat::Utf8Lossy => {
                    println!("{}", String::from_utf8_lossy(&matched_data));
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), String> {
    run(Options::parse())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use assert_fs::prelude::*;

    #[test]
    fn test_generate_key_pair() {
        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd.args(&["generate-key-pair"]).output().unwrap();

        let key_pair: KeyPair =
            serde_json::from_str(std::str::from_utf8(&out.stdout).unwrap()).unwrap();

        radix64::STD.decode(&key_pair.private_key).unwrap();
        radix64::STD.decode(&key_pair.public_key).unwrap();
    }

    #[test]
    fn test_decrypt() {
        let matched_data = "test matched data";
        // Encrypted with public key:
        // Ycig/Zr/pZmklmFUN99nr+taURlYItL91g+NcHGYpB8=
        let encrypted_matched_data = "AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk=";
        let private_key = "uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=";

        let temp_dir = assert_fs::TempDir::new().unwrap();
        let encrypted_matched_data_file = temp_dir.child("encrypted_matched_data.txt");
        encrypted_matched_data_file
            .write_str(encrypted_matched_data)
            .unwrap();
        let private_key_file = temp_dir.child("private_key.txt");
        private_key_file.write_str(private_key).unwrap();

        // Matched data key in file
        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                encrypted_matched_data_file.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert_eq!(
            format!("{}\n", matched_data),
            str::from_utf8(&out.stdout).unwrap()
        );

        // Matched data key in stdin
        cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                "-",
            ])
            .write_stdin(encrypted_matched_data)
            .output()
            .unwrap();

        assert_eq!(
            format!("{}\n", matched_data),
            str::from_utf8(&out.stdout).unwrap()
        );

        temp_dir.close().unwrap();
    }
}
