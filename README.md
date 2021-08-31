# Matched Data CLI

Tool to interact with the firewall matched data feature.

## Setup

`cargo build`

## Test

`cargo test`

## Usage

``` plain
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
$ cat private_key.txt
uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=
$ cat matched_data.txt
AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk=
$ matched-data-cli decrypt -k private_key.txt matched_data.txt
test matched data
```

or using stdin, for example:

``` shell
$ cat private_key.txt
uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=
$ printf 'AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk=' | matched-data-cli decrypt -k private_key.txt -
test matched data
```
