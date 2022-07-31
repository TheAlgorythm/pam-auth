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

fn convert_err(error: &dyn Display, flags: &PamFlags) -> PamError {
    if !flags.contains(PamFlags::SILENT) {
        println!("Error: {}", error);
    }
    PamError::AUTH_ERR
}

struct PamPin;

impl PamPin {
    fn get_pin(pamh: &Pam) -> PamResult<&CStr> {
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
            .ok_or_else(|| convert_err(&"No username", &flags))?
            .to_str()
            .map_err(|e| convert_err(&e, &flags))?;
        let users_data = pin_data::Data::from_file(&"/etc/security/pins.toml")
            .map_err(|e| convert_err(&e, &flags))?;
        let user = users_data
            .get_by_name(user_name)
            .ok_or_else(|| convert_err(&"No user in database", &flags))?;

        let pin = Self::get_pin(&pamh)?;

        Self::verify_pin(user.pin_hash(), pin.to_bytes()).map_err(|e| convert_err(&e, &flags))?;
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
