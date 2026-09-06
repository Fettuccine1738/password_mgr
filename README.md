# pass_man

A command-line password manager written in Rust, focused on getting the
cryptography and state handling right: vaults are encrypted at rest with
AES-GCM, keys are derived from a master password with Argon2, and locked
vs. unlocked vault state is enforced at the type level.

## Features

- **Encrypted vault storage** — secrets are serialized, then encrypted with
  AES-256-GCM before ever touching disk. Each vault file stores a random
  salt, a per-encryption nonce, and the authenticated ciphertext.
- **Key derivation via Argon2** — the master password never derives the
  same key twice without the same salt; wrong-password and corrupt-data
  failures are distinguished so users get accurate error feedback.
- **Locked/Unlocked state machine** — vault state is modeled as an enum
  (`Locked`, `Unlocked`, `Limbo`) so a vault's secrets are only ever
  reachable through an `UnlockedVault`, and locking always re-encrypts
  with a fresh nonce (nonce reuse under the same key is a hard rule this
  project enforces by construction, not convention).
- **Simple REPL interface** — create a vault, sign in, add a secret, fetch a
  secret by website, sign out, or quit through a numbered menu.
- **Secret updates with confirmation** — adding a secret for a website that
  already exists prompts for confirmation before replacing the existing
  secret. Declining leaves the original secret unchanged.
- **Automatic persistence** — successfully adding a new or updated secret
  snapshots the unlocked vault, encrypts it, and writes the vault file to
  `~/.pass_mgr/`.
- **Testable I/O boundary** — user input is behind an `InputSource` trait
  with a mock implementation, so vault logic can be tested without a
  real terminal.

## How it works

```
LockedVault  { name, salt, kdf_params, nonce, ciphertext }
     |  unlock(password)
     v
UnlockedVault { name, key, salt, kdf_params, secrets }
     |  lock()  — generates a fresh nonce, re-encrypts
     v
LockedVault (new nonce, new ciphertext)
```

### CLI workflow

When the program starts, choose an action from the numbered menu:

1. Create a new vault. Provide a vault name and confirm the master password.
2. Sign in to an existing vault with its master password.
3. Add a secret by entering a username or email, password, and website. The
   vault is saved after a successful add. If the website already exists, answer
   `y` or `yes` to update it, or `n`/`no` to keep the existing secret.
4. Fetch a secret by website while the vault is unlocked.
5. Sign out and return to the locked/limbo state.
6. Quit the program.

Newly created and modified vaults are persisted immediately after a successful
secret add or update. Signing out clears the unlocked vault from the active
CLI state.

On-disk vault file layout:

```
[ salt (16 bytes) ][ nonce (12 bytes) ][ AES-GCM ciphertext + auth tag ]
```

## Getting started

```bash
git clone git@github.com:Fettuccine1738/password_mgr.git
cd password_mgr
cargo build
cargo run
```

Vault files are stored in a local vault directory (created automatically
on first run) and should never be edited by hand — see the `README.md`
generated inside that directory for details.

## Running tests

```bash
cargo test
```

Integration tests exercise vault creation, locking/unlocking, secret
add/update confirmation, encrypted persistence to disk, and serialization
round-trips against temp files; unit tests cover serialization edge cases and
encryption primitives directly.

## Project status

This is an actively developed learning/portfolio project — the core
crypto flow (create → lock → unlock → save) works end-to-end, with
ongoing work on the CLI's error handling and edge cases around vault
file management.

## Security notes

- This project is a learning exercise in applied cryptography and Rust's
  type system, not an audited, production-grade password manager. Don't
  use it to store real, high-value secrets.
- AES-GCM authentication means any corruption to a vault file — even a
  single flipped bit — makes it permanently undecryptable. Back up vault
  files as opaque blobs; never edit them.
