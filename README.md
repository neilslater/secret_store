# SecretStore

[![Build Status](https://travis-ci.org/neilslater/secret_store.png?branch=master)](http://travis-ci.org/neilslater/secret_store)

Ruby project for storing small secret messages accessed with a master password, using standard cryptgraphic components.
This is a hobby project to help understand correct use of those components.

It can be used like a password locker, with all passwords stored under logical keys. The level of
secrecy using encryption at rest is essentially as strong as the master password used.

The base encryption uses OpenSSL library AES 256 GCM, and keys are derived from a master password
using Bcrypt to generate an interim master checksum, followed by PBKDF2 HMAC SHA256 to convert that
checksum into a unique key per stored secret. The master password is also verified against a
stored random message - this is so that all messages are encrypted based on the same master password.

When the application is not in use, the stored secrets in the database
or exported as YAML should be inaccessible without the master password, and brute-forcing that password
is made harder by use of a moderately high Bcrypt work factor (14).

Note this project cannot protect against compromised host environment whilst running - e.g. a keylogger,
code insertion into Ruby, or targetting code in this library installed on the host machine are all attacks that can be used to
obtain the master password.

There is no way to recover from a forgotten password - if that happens your secrets will
become unreadable.

## Disclaimer

This code has been created primarily for learning purposes.

I do not accept liability for lost passwords, or leaked data when using this code. I do not
recommend it is used for managing important messages, such as system passwords. There are better
open-source and commercial systems available for those purposes that provide increased secrecy *during*
use of the product, where this Ruby script is vulnerable.

## Usage

### Command line console app (uses irb, with command history disabled)

    ./console [secrets_file]

Uses command line argument, or value of ```SECRET_STORE_FILE``` environment variable, as location
of SQLite database. You will be prompted for a password. For initial file, this sets the password
in use. For existing file, the password must match (this is not the protection for the content,
it is to ensure all key generation works from the same initial password).

This is just a Ruby ```irb``` session with a few added methods for managing secrets. The available
methods are explained on successful start. All parameters should be Strings.

You can place a variation of ```console``` with a different name e.g. ```secret_store``` on
the path, and set ```SECRET_STORE_FILE``` in ```.bash_profile```.

## License

The project is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
