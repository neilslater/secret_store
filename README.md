# SecretStore

[![CI](https://github.com/neilslater/secret_store/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/neilslater/secret_store/actions/workflows/ci.yml)

Ruby application for storing small secret messages accessed with a master password, using
standard cryptographic components. This is a hobby project for learning their correct use.
It runs from this repository; it is not currently packaged or published as a RubyGem.

## Security and storage

Secret payloads are encrypted with OpenSSL AES-256-GCM. BCrypt (default cost 14) derives
an interim master checksum, and PBKDF2-HMAC-SHA256 with 10,000 iterations derives each
32-byte encryption key using a random salt. A stored random encrypted message verifies
the master password. The cipher, derivation parameters, SQLite schema, and encrypted
compatibility fixtures retain their existing representation.

Labels are authenticated but readable. Secret counts, ciphertext lengths, salts, IVs,
and password-verification material are also visible in SQLite files and YAML backups.
The format detects authenticated-record tampering during decryption, but does not prove
whole-store completeness or freshness: deletion, rollback, and replacement with an older
valid record are not detected. Password rotation does not revoke old backups, which still
require the password used when they were created.

The application cannot protect a compromised host or Ruby process. A keylogger, injected
code, or modified library can capture plaintext or derived keys. There is no password
recovery mechanism; a forgotten password makes its encrypted secrets unreadable.

Encrypted records require complete fields, valid URL-safe Base64, 16-byte PBKDF2 salts,
and full 16-byte GCM authentication tags. Malformed records raise `SecretStore::FormatError`
(a `RuntimeError`); structural validation alone does not authenticate data. Decryption
must succeed with the key before plaintext is returned. Secret replacement leaves the
original encrypted record unchanged if encryption fails. Writers retain the legacy
16-byte stored IV representation and use its first 12 bytes as the GCM nonce.

## Transactions

Connection operations use SQLite transactions. Password rotation commits all encrypted
records and the new password together, then publishes the new session key. Reads, writes,
deletes, and rotations reject connections whose stored password record has changed; reconnect
to continue. Initial password creation is serialized and rejects orphan secrets. Lock waits
are bounded to five seconds (`SQLite3::BusyException` on timeout). Nested or caller-owned
transactions are rejected before work; share a store through separate connections/handles,
not simultaneous operations on one handle. Low-level `Store` saves atomically upsert encrypted
records but do not verify the caller's key or enforce session identity. Rotation cannot revoke
keys already held in memory or old backups.

## Restoration

YAML restoration populates an empty destination; occupied stores (including password-only
stores) are rejected instead of merged or replaced. `Store.import_yaml` validates encrypted
record structure without a password. `Connection.init_from_yaml` additionally authenticates
the password and every secret before opening the destination. Empty exports use
`master_password: null` and `secrets: []` with the existing symbol keys; historical empty
hashes remain readable. Installation uses one transaction. SQL failures close the internally
opened handle and roll back all records; a newly initialized empty SQLite file is retained
for inspection or retry. Failure cleanup never deletes destination files.

## Backup files

Backups read a coherent SQLite snapshot and serialize it before touching the output file.
Export rejects database/sidecar destinations, hard-link aliases, symlinks, non-regular targets,
and targets owned by another user. Complete backups are published by same-directory atomic
rename from an exclusively created `0600` temporary file, after flush, file fsync, and close.
Ordinary write/close/rename failures preserve the old backup and remove the temporary file.
Directory fsync and universal power-loss durability are not promised. Use directories you
control; pathname checks do not defend against a hostile process replacing directory entries.

New file-backed databases use exclusive creation with mode `0600`, without changing the
process umask. Pre-existing database permissions are preserved; review and restrict broad
permissions yourself if appropriate. Normal filenames (including `Pathname`), `:memory:`,
and an empty filename for SQLite temporary databases are supported. SQLite `file:` URI
connection strings are explicitly rejected; use an ordinary filename instead.

## Disclaimer

This code has been created primarily for learning purposes.

I do not accept liability for lost passwords, or leaked data when using this code. I do not
recommend it is used for managing important messages, such as system passwords. There are better
open-source and commercial systems available for those purposes that provide increased secrecy *during*
use of the product, where this Ruby script is vulnerable.

## Usage

SecretStore requires Ruby 3.3 or newer and the dependencies in the committed Bundler lockfile.
Install them with `bundle install` using your selected Ruby before launching the console.

### Command line console app (uses irb, with command history disabled)

    ./console [secrets_file]

The explicit filename takes precedence over `SECRET_STORE_FILE`. If neither is supplied,
the database defaults to `~/secrets.sqlite3.dat`. The password prompt establishes the master
password for an empty store or verifies it for an existing store. New passwords require at
least eight characters; existing stores retain their password compatibility.

The wrapper uses the committed bundle and resolves application files relative to itself.
Relative database paths remain relative to your working directory. User IRB startup RC
files are disabled, as is disk command history. Password entry uses a fixed acknowledgement;
EOF raises `EOFError` before loading or changing a store, and terminal echo is restored by
`IO#noecho` on EOF or interruption. Object inspection and pretty printing omit derived keys.
This does not erase in-memory values, hide typed Ruby commands or deliberate secret reads,
or protect terminal scrollback. IRB remains an unrestricted Ruby session.

The console prints available helper methods on startup. Labels passed to helpers are converted
to Strings; record constructors require String labels. `read_secret` returns nil for an absent
label. Use `export_secrets 'backup.yml'` to export explicitly, or `export_secrets` to use
`SECRET_EXPORT_FILE`, falling back to `~/secrets_export.yml`. Relative paths are relative to
the caller's working directory. The console wrapper must remain in the checkout beside its
`Gemfile`, `lib/`, and `bin/` directories; a shell alias can invoke it by its full path.

## License

The project is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
