#[macro_use]
extern crate pamsm;

mod args;

use argon2::{password_hash, Argon2};
use pam_utils::IntoPamError;
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamResult, PamServiceModule};
use password_hash::PasswordHash;
use std::ffi::CStr;

struct PamPin;

impl PamPin {
    #[cfg(feature = "sandbox")]
    fn setup_sandbox(args: &args::Args) -> birdcage::error::Result<()> {
        use birdcage::{Birdcage, Sandbox};

        let mut birdcage = Birdcage::new()?;

        birdcage.add_exception(birdcage::Exception::Read(args.database_filepath.clone()))?;

        birdcage.lock()
    }

    fn get_user_pin(pamh: &Pam) -> PamResult<&CStr> {
        pamh.conv(Some("Pin: "), pamsm::PamMsgStyle::PROMPT_ECHO_OFF)?
            .ok_or(PamError::AUTHTOK_RECOVERY_ERR)
    }

    fn verify_pin(hash: PasswordHash<'_>, pin: &[u8]) -> password_hash::errors::Result<()> {
        hash.verify_password(&[&Argon2::default()], pin)
    }

    fn auth(pamh: &Pam, flags: PamFlags, args: Vec<String>) -> Result<(), PamError> {
        let args: args::Args = args.try_into().pam_custom_err(PamError::IGNORE, &flags)?;

        #[cfg(feature = "sandbox")]
        Self::setup_sandbox(&args).pam_err(&flags)?;

        let user_name = pam_utils::get_username(pamh, &flags)?;
        let users_data = pin_data::Data::from_file(&args.database_filepath).pam_err(&flags)?;
        let user = users_data
            .get_by_name(&user_name)
            .ok_or(PamError::USER_UNKNOWN)?;

        let pin = Self::get_user_pin(pamh)?;

        Self::verify_pin(user.pin_hash(), pin.to_bytes()).pam_err(&flags)?;
        Ok(())
    }
}

impl PamServiceModule for PamPin {
    fn authenticate(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        pam_utils::do_call_handler(Self::auth, pamh, flags, args)
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
        let hash = PasswordHash::new(hash).unwrap();

        PamPin::verify_pin(hash, pin.as_bytes()).unwrap();
    }

    #[test]
    fn not_verify_invalid_hash() {
        let hash = "foo";
        PasswordHash::new(hash).unwrap_err();
    }

    #[test]
    fn not_verify_invalid_pin() {
        let pin = "Pw";
        let hash = "$argon2d$v=19$m=4096,t=3,p=1$PFRID+hbQKjEFESZWQZMEA$mMpICfZn5N0bV13RJ3nWYfYXesgTJcPl81xwrqzDDLY";
        let hash = PasswordHash::new(hash).unwrap();

        PamPin::verify_pin(hash, pin.as_bytes()).unwrap_err();
    }
}
