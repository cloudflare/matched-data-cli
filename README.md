# Matched Data CLI

Tool to interact with the firewall matched data feature.

## Setup

`cargo build`

## Test

`cargo test`

## Usage

```
USAGE:
    matched-data-cli <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt              Decrypts data
    generate-key-pair    Generates a public-private key pair
    help                 Prints this message or the help of the given subcommand(s)
```

To generate a key pair:

``` shell
$ matched-data-cli generate-key-pair
{
  "private_key": "uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=",
  "public_key": "Ycig/Zr/pZmklmFUN99nr+taURlYItL91g+NcHGYpB8="
}
```

To decrypt an encrypted matched data blob:

``` shell
$ matched-data-cli decrypt -d AdfVn7odpamJGeFAGj0iW2oTtoXOjVnTFT2x4l+cHKJsEQAAAAAAAAB+zDygjV2aUI92FV4cHMkp+4u37JHnH4fUkRqasPYaCgk= -k $PRIVATE_KEY
test matched data
```

or using stdin, for example:

``` shell
$ printf $PRIVATE_KEY | matched-data-cli decrypt -d AdfVn7odpamJGeFAGj0iW2oTtoXOjVnTFT2x4l+cHKJsEQAAAAAAAAB+zDygjV2aUI92FV4cHMkp+4u37JHnH4fUkRqasPYaCgk= --private-key-stdin
test matched data
```
