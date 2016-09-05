# SecretStore

[![Build Status](https://travis-ci.org/neilslater/secret_store.png?branch=master)](http://travis-ci.org/neilslater/secret_store)

Ruby project for storing small secrets accessed with a master password, using standard cryptgraphic components.

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
