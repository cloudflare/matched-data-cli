#![warn(rust_2018_idioms)]

mod matched_data;

use crate::matched_data::generate_key_pair;
use clap::Clap;
use hpke::kex::Serializable;
use serde::{Deserialize, Serialize};
use std::io::{stdin, stdout, Write};
use std::str;

#[derive(Clap)]
#[clap(author, version)]
struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Clap)]
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

#[derive(Clap)]
enum DecryptOutputFormat {
    Raw,
    Utf8Lossy,
}

#[derive(Clap)]
struct DecryptOptions {
    #[clap(short = 'd', long, about = "Base64 encoded encrypted matched data")]
    matched_data: String,

    #[clap(
        short = 'k',
        long,
        about = "Base64 encoded private key",
        conflicts_with = "private-key-stdin"
    )]
    private_key: Option<String>,

    #[clap(
        long,
        about = "Whether to read the private key from stdin",
        required_unless_present = "private-key"
    )]
    private_key_stdin: bool,

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
            let private_key_base64: String = if command.private_key_stdin {
                let mut buffer = String::new();
                stdin()
                    .read_line(&mut buffer)
                    .expect("Failed to read private key from stdin");
                buffer
            } else {
                command.private_key.unwrap()
            };

            let private_key_bytes = radix64::STD
                .decode(&private_key_base64)
                .map_err(|_| "Provided private key is not base64 encoded")?;

            let encrypted_matched_data_bytes = radix64::STD
                .decode(&command.matched_data)
                .map_err(|_| "Provided matched data is not base64 encoded")?;

            macro_rules! decrypt {
                ($modname:ident) => {{
                    use $modname::{
                        decrypt_data, deserialize_encrypted_data, get_private_key_from_bytes,
                    };

                    let private_key = get_private_key_from_bytes(&private_key_bytes)
                        .map_err(|_| "Provided private key is invalid")?;

                    // Validate and construct encrypted matched data from input
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

        // Private key in argument
        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&["decrypt", "-d", encrypted_matched_data, "-k", private_key])
            .output()
            .unwrap();

        assert_eq!(
            format!("{}\n", matched_data),
            str::from_utf8(&out.stdout).unwrap()
        );

        // Private key in stdin
        cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-d",
                encrypted_matched_data,
                "--private-key-stdin",
            ])
            .write_stdin(private_key)
            .output()
            .unwrap();

        assert_eq!(
            format!("{}\n", matched_data),
            str::from_utf8(&out.stdout).unwrap()
        );
    }

    #[test]
    fn test_arguments() {
        let encrypted_matched_data = "Ah0Ax4UEtSQg/bVSJHcgIwbLoNNKGbcwpL2BdCPJEYx1EQAAAAAAAAAsrRpY63jVlKash1iJ2bYh6+TQtedI380nnmZAWYgZMIU=";
        let private_key = "uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=";

        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();

        // '--private-key <private-key>' requires a value but none was supplied
        cmd.args(&["decrypt", "-d", "-k", private_key]).unwrap_err();

        // '--private-key <private-key>' requires a value but none was supplied
        cmd.args(&["decrypt", "-d", encrypted_matched_data, "-k"])
            .unwrap_err();

        // '--private-key <private-key>' cannot be used with '--private-key-stdin'
        cmd.args(&[
            "decrypt",
            "-d",
            encrypted_matched_data,
            "-k",
            private_key,
            "private-key-stdin",
        ])
        .unwrap_err();
    }
}
