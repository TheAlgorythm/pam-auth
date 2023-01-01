#[macro_use]
extern crate pamsm;
#[macro_use]
extern crate pam_utils;

use argon2::{password_hash, Argon2};
use pam_utils::IntoPamError;
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamResult, PamServiceModule};
use password_hash::PasswordHash;
use std::ffi::CStr;
use std::path::PathBuf;

struct Args {
    pub database_filepath: PathBuf,
}

impl Args {
    const DATABASE_FILEPATH_ID: &'static str = "db=";
    const DATABASE_MISSING: &'static str = "There is no `db=/<file>` given.";
}

impl TryFrom<Vec<String>> for Args {
    type Error = &'static str;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let database_filepath = pam_utils::extract_named_value(&value, Self::DATABASE_FILEPATH_ID)
            .ok_or(Self::DATABASE_MISSING)?
            .into();

        Ok(Self { database_filepath })
    }
}

struct PamPin;

impl PamPin {
    fn get_user_pin(pamh: &Pam) -> PamResult<&CStr> {
        pamh.conv(Some("Pin: "), pamsm::PamMsgStyle::PROMPT_ECHO_OFF)?
            .ok_or(PamError::AUTHTOK_RECOVERY_ERR)
    }

    fn verify_pin(hash: &str, pin: &[u8]) -> password_hash::errors::Result<()> {
        let hash = PasswordHash::new(hash)?;

        hash.verify_password(&[&Argon2::default()], pin)
    }

    fn auth(pamh: Pam, flags: PamFlags, args: Vec<String>) -> Result<(), PamError> {
        let args: Args = args.try_into().pam_custom_err(PamError::IGNORE, &flags)?;

        let user_name = pam_utils::get_username(&pamh, &flags)?;
        let users_data = pin_data::Data::from_file(&args.database_filepath).pam_err(&flags)?;
        let user = users_data
            .get_by_name(&user_name)
            .ok_or(PamError::USER_UNKNOWN)?;

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
