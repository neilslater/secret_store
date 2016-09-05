# SecretStore

[![Build Status](https://travis-ci.org/neilslater/secret_store.png?branch=master)](http://travis-ci.org/neilslater/secret_store)

Ruby project for storing small secrets accessed with a master password, using standard cryptgraphic components.
This is a hobby project to help understand correct use of the components, but also I wanted an alternative
to password locker applications where I better understood the source code and limitations.

It can be used like a password locker, with all passwords stored under logical keys. The level of
secrecy using encryption at rest is essentially as strong as the master password used.

The base encryption uses OpenSSL library AES 256 CBC, and keys are derived from a master password
using PBKDF HMAC SHA256 (100,000 iterations). The master password is also verified against a stored
bcrypt hash (work factor 14) - although the module will treat this a bit like authentication for
convenience, that is not what is going on, the password is just being verified before use so that
all secrets are encrypted based on the same starting value.

Note this project cannot protect against compromised host environment - e.g. a keylogger, code insertion into Ruby
(or an attack targetting code in this library installed on the host machine) can work around the protection,
which is just encryption at rest of the contained secrets.

There is no way to recover from a forgotten password - if that happens your secrets will
become unreadable. Bear that in mind, and use at own risk.

## Usage

### Command line console app (uses irb)

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
