# [WiP] PAM Modules written in Rust

## [PAM Pin](pam-pin)

A module for using pins different from `/etc/shadow`.
Even though it uses the much stronger `Argon2d` password hashing function by default, short pins[^1] shouldn't be used without MFA[^2].
[Pin Gen](pin-gen) can be used to generate the database.
Please use the recommendations of `pin-gen --help`.

[^1]: ⪅ 8 characters (alphanumeric)
[^2]: Multi-factor-authentication

## [PAM Direct Fallback](pam-direct-fallback)

This module can be used to make PAM statefull.
If you want to have an easy authentication path with e. g. pin, [Howdy](https://github.com/boltgolt/howdy) and a FIDO2 USB security key
and a hard path with your password, then this will make sure that the easy path can only be triggered once.
After a successful login the user-state will be resetted.

## Install

The Rust compiler has to be installed.

```console
$ cargo build --release
```

The binary of `pin-gen` and the PAM modules are now in the `target/release` folder.

To install `pin-gen` in `$PATH`:

```console
$ cargo install --path pin-gen
```

The modules have to be copied to the PAM modules folder (e.g. `/lib/security`).
For testing the configuration, the [pamtester](https://pamtester.sourceforge.net/) utility is advisable.

