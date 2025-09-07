#[macro_use]
extern crate pamsm;

mod args;

use argon2::{password_hash, Argon2};
use error_stack::{Report, ResultExt};
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use password_hash::PasswordHash;
use secstr::SecStr;

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

type Result<T> = std::result::Result<T, Report<Error>>;

struct PamPin;

impl PamPin {
    #[cfg(feature = "sandbox")]
    fn setup_sandbox(args: &args::Args) -> Result<()> {
        use birdcage::{Birdcage, Sandbox};

        let mut birdcage = Birdcage::new()
            .change_context(Error::Sandbox)
            .attach("Initialization failed")?;

        birdcage
            .add_exception(birdcage::Exception::Read(args.database_filepath.clone()))
            .change_context(Error::Sandbox)
            .attach("Couldn't set the database file as readable")?;

        birdcage
            .lock()
            .change_context(Error::Sandbox)
            .attach("Couldn't activate sandbox")
    }

    fn get_user_pin(pamh: &Pam) -> Result<SecStr> {
        pamh.conv(Some("Pin: "), pamsm::PamMsgStyle::PROMPT_ECHO_OFF)
            .map_err(|pam_code| Report::new(Error::Pam).attach_opaque(pam_code))?
            .map(|pin| SecStr::from(pin.to_bytes()))
            .ok_or(Error::ReadPassword)
            .attach_opaque(PamError::AUTHTOK_RECOVERY_ERR)
    }

    fn verify_pin(hash: &PasswordHash<'_>, pin: &SecStr) -> Result<()> {
        hash.verify_password(&[&Argon2::default()], pin.unsecure())
            .change_context(Error::VerifyPassword)
    }

    fn auth(pamh: &Pam, _flags: PamFlags, args: Vec<String>) -> Result<()> {
        let args = args::Args::try_from(args).attach_opaque(PamError::IGNORE)?;

        #[cfg(feature = "sandbox")]
        Self::setup_sandbox(&args)?;

        let user_name = pam_utils::get_username(pamh, Error::Pam, Error::UnknownUser)?;
        let users_data = pin_data::Data::from_file(&args.database_filepath)
            .change_context(Error::LoadDatabase)?;
        let user = users_data
            .get_by_name(&user_name)
            .ok_or(Error::UnknownUser)
            .attach_opaque(PamError::USER_UNKNOWN)?;

        let pin = Self::get_user_pin(pamh)?;

        Self::verify_pin(&user.pin_hash(), &pin)?;
        drop(pin);
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
        let pin = SecStr::from("pw");
        let hash = "$argon2d$v=19$m=4096,t=3,p=1$PFRID+hbQKjEFESZWQZMEA$mMpICfZn5N0bV13RJ3nWYfYXesgTJcPl81xwrqzDDLY";
        let hash = PasswordHash::new(hash).unwrap();

        PamPin::verify_pin(&hash, &pin).unwrap();
    }

    #[test]
    fn not_verify_invalid_hash() {
        let hash = "foo";
        PasswordHash::new(hash).unwrap_err();
    }

    #[test]
    fn not_verify_invalid_pin() {
        let pin = SecStr::from("Pw");
        let hash = "$argon2d$v=19$m=4096,t=3,p=1$PFRID+hbQKjEFESZWQZMEA$mMpICfZn5N0bV13RJ3nWYfYXesgTJcPl81xwrqzDDLY";
        let hash = PasswordHash::new(hash).unwrap();

        let _ = PamPin::verify_pin(&hash, &pin).unwrap_err();
    }
}
