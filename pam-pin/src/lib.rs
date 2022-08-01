#[macro_use]
extern crate pamsm;

use argon2::{password_hash, Argon2};
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamResult, PamServiceModule};
use password_hash::PasswordHash;
use std::ffi::CStr;
use std::fmt::Display;

macro_rules! err_try {
    ($res:expr) => {
        match $res {
            Ok(res) => res,
            Err(e) => return e,
        }
    };
}

trait ToPamError<T> {
    fn pam_err(self, flags: &PamFlags) -> Result<T, PamError>;
}

impl<T, E: Display> ToPamError<T> for Result<T, E> {
    fn pam_err(self, flags: &PamFlags) -> Result<T, PamError> {
        self.map_err(|error| {
            if !flags.contains(PamFlags::SILENT) {
                println!("Error: {}", error);
            }
            PamError::AUTH_ERR
        })
    }
}

struct PamPin;

impl PamPin {
    fn get_user_pin(pamh: &Pam) -> PamResult<&CStr> {
        pamh.get_authtok(Some("Pin: "))?
            .ok_or(PamError::AUTHTOK_RECOVERY_ERR)
    }

    fn verify_pin(hash: &str, pin: &[u8]) -> password_hash::errors::Result<()> {
        let hash = PasswordHash::new(hash)?;

        hash.verify_password(&[&Argon2::default()], pin)
    }

    fn auth(pamh: Pam, flags: PamFlags, _args: Vec<String>) -> Result<(), PamError> {
        let user_name = pamh
            .get_user(None)?
            .ok_or("No username")
            .pam_err(&flags)?
            .to_str()
            .pam_err(&flags)?;
        let users_data = pin_data::Data::from_file(&"/etc/security/pins.toml").pam_err(&flags)?;
        let user = users_data
            .get_by_name(user_name)
            .ok_or("No user in database")
            .pam_err(&flags)?;

        let pin = Self::get_user_pin(&pamh)?;

        Self::verify_pin(user.pin_hash(), pin.to_bytes()).pam_err(&flags)?;
        Ok(())
    }
}

impl PamServiceModule for PamPin {
    fn authenticate(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        err_try!(Self::auth(pamh, flags, args));
        PamError::SUCCESS
    }
}

pam_module!(PamPin);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_valid_pin() {
        let pin = "pw";
        let hash = "$argon2d$v=19$m=4096,t=3,p=1$PFRID+hbQKjEFESZWQZMEA$mMpICfZn5N0bV13RJ3nWYfYXesgTJcPl81xwrqzDDLY";

        PamPin::verify_pin(hash, pin.as_bytes()).unwrap();
    }

    #[test]
    fn not_verify_invalid_hash() {
        let pin = "pw";
        let hash = "foo";

        PamPin::verify_pin(hash, pin.as_bytes()).unwrap_err();
    }

    #[test]
    fn not_verify_invalid_pin() {
        let pin = "Pw";
        let hash = "$argon2d$v=19$m=4096,t=3,p=1$PFRID+hbQKjEFESZWQZMEA$mMpICfZn5N0bV13RJ3nWYfYXesgTJcPl81xwrqzDDLY";

        PamPin::verify_pin(hash, pin.as_bytes()).unwrap_err();
    }
}
