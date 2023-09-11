#[macro_use]
extern crate pamsm;

mod args;

use argon2::{password_hash, Argon2};
use error_stack::{Report, ResultExt};
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use password_hash::PasswordHash;
use std::ffi::CStr;

#[derive(thiserror::Error, Debug, Clone)]
enum Error {
    #[error("A panic happened in the sandboxed thread")]
    SandboxPanic,
    #[error("There is no `db=/<file>` given.")]
    MissingDatabaseArg,
    #[error("Couldn't build sandbox")]
    Sandbox,
    #[error("Internal PAM error")]
    Pam,
    #[error("Couldn't load database")]
    LoadDatabase,
    #[error("User not known")]
    UnknownUser,
    #[error("Couldn't read password")]
    ReadPassword,
    #[error("Couldn't verify password")]
    VerifyPassword,
}

type Result<T> = error_stack::Result<T, Error>;

struct PamPin;

impl PamPin {
    #[cfg(feature = "sandbox")]
    fn setup_sandbox(args: &args::Args) -> Result<()> {
        use birdcage::{Birdcage, Sandbox};

        let mut birdcage = Birdcage::new()
            .change_context(Error::Sandbox)
            .attach_printable("Initialization failed")?;

        birdcage
            .add_exception(birdcage::Exception::Read(args.database_filepath.clone()))
            .change_context(Error::Sandbox)
            .attach_printable("Couldn't set the database file as readable")?;

        birdcage
            .lock()
            .change_context(Error::Sandbox)
            .attach_printable("Couldn't activate sandbox")
    }

    fn get_user_pin(pamh: &Pam) -> Result<&CStr> {
        pamh.conv(Some("Pin: "), pamsm::PamMsgStyle::PROMPT_ECHO_OFF)
            .map_err(|pam_code| Report::new(Error::Pam).attach(pam_code))?
            .ok_or(Error::ReadPassword)
            .attach(PamError::AUTHTOK_RECOVERY_ERR)
    }

    fn verify_pin(hash: PasswordHash<'_>, pin: &[u8]) -> Result<()> {
        hash.verify_password(&[&Argon2::default()], pin)
            .change_context(Error::VerifyPassword)
    }

    fn auth(pamh: &Pam, _flags: PamFlags, args: Vec<String>) -> Result<()> {
        let args = args::Args::try_from(args).attach(PamError::IGNORE)?;

        #[cfg(feature = "sandbox")]
        Self::setup_sandbox(&args)?;

        let user_name = pam_utils::get_username(pamh, Error::Pam, Error::UnknownUser)?;
        let users_data = pin_data::Data::from_file(&args.database_filepath)
            .change_context(Error::LoadDatabase)?;
        let user = users_data
            .get_by_name(&user_name)
            .ok_or(Error::UnknownUser)
            .attach(PamError::USER_UNKNOWN)?;

        let pin = Self::get_user_pin(pamh)?;

        Self::verify_pin(user.pin_hash(), pin.to_bytes())?;
        Ok(())
    }
}

impl PamServiceModule for PamPin {
    fn authenticate(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        pam_utils::do_call_handler(Self::auth, pamh, flags, args, Error::SandboxPanic)
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

        let _ = PamPin::verify_pin(hash, pin.as_bytes()).unwrap_err();
    }
}
