#[macro_use]
extern crate pamsm;

mod args;

use args::Args;
use error_stack::{Report, ResultExt};
use pam_utils::do_call_handler;
use pamsm::{Pam, PamError, PamFlags, PamServiceModule};
use path_ratchet::prelude::*;
use std::fs::{remove_file, File};
use std::path::PathBuf;

#[derive(thiserror::Error, Debug, Clone)]
enum Error {
    #[error("A panic happened in the sandboxed thread")]
    SandboxPanic,
    #[error("There is no `store=/<dir>` given.")]
    MissingUserStoreArg,
    #[error("Couldn't build sandbox")]
    Sandbox,
    #[error("Internal PAM error")]
    Pam,
    #[error("User not known")]
    UnknownUser,
    #[error("Username has dissalowed characters")]
    InvalidUsername,
    #[error("Couldn't authenticate the user")]
    Auth,
    #[error("Couldn't reset the account authentication state")]
    Reset,
}

type Result<T> = error_stack::Result<T, Error>;

fn user_file(dir: PathBuf, username: String) -> Result<PathBuf> {
    let mut user_data_file = dir;
    let user_file_name = SingleComponentPath::new(&username).ok_or(Error::InvalidUsername)?;
    user_data_file.push_component(user_file_name);
    Ok(user_data_file)
}

struct PamDirectFallback;

impl PamDirectFallback {
    fn start_session(pamh: &Pam, _flags: PamFlags, args: Vec<String>) -> Result<()> {
        let args = Args::try_from(args).attach(PamError::IGNORE)?;

        #[cfg(feature = "sandbox")]
        Self::setup_sandbox(&args)?;

        let username = pam_utils::get_username(pamh, Error::Pam, Error::UnknownUser)?;

        let user_data_file = user_file(args.user_store, username)?;

        Self::reset(user_data_file)
    }

    fn auth(pamh: &Pam, _flags: PamFlags, args: Vec<String>) -> Result<()> {
        let args = Args::try_from(args).attach(PamError::IGNORE)?;

        #[cfg(feature = "sandbox")]
        Self::setup_sandbox(&args)?;

        let username = pam_utils::get_username(pamh, Error::Pam, Error::UnknownUser)?;

        let user_data_file = user_file(args.user_store, username)?;

        if args.reset {
            Self::reset(user_data_file)
        } else {
            Self::set(user_data_file)
        }
    }

    #[cfg(feature = "sandbox")]
    fn setup_sandbox(args: &args::Args) -> Result<()> {
        use birdcage::{Birdcage, Sandbox};

        let mut birdcage = Birdcage::new()
            .change_context(Error::Sandbox)
            .attach_printable("Initialization failed")?;

        birdcage
            .add_exception(birdcage::Exception::Write(args.user_store.clone()))
            .change_context(Error::Sandbox)
            .attach_printable("Couldn't set the user store as writeable")?;

        birdcage
            .lock()
            .change_context(Error::Sandbox)
            .attach_printable("Couldn't activate sandbox")
    }

    fn set(user_data_file: PathBuf) -> Result<()> {
        File::options()
            .write(true)
            .create_new(true)
            .open(user_data_file)
            .map(|_| ())
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => Report::new(e)
                    .change_context(Error::Auth)
                    .attach(PamError::AUTH_ERR),
                _ => Report::new(e).change_context(Error::Auth),
            })
    }

    fn reset(user_data_file: PathBuf) -> Result<()> {
        remove_file(user_data_file).change_context(Error::Reset)
    }
}

impl PamServiceModule for PamDirectFallback {
    fn open_session(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        do_call_handler(Self::start_session, pamh, flags, args, Error::SandboxPanic)
    }

    fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn authenticate(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        do_call_handler(Self::auth, pamh, flags, args, Error::SandboxPanic)
    }
}

pam_module!(PamDirectFallback);
