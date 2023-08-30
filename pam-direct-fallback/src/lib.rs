#[macro_use]
extern crate pamsm;

mod args;
mod path;

use args::Args;
use pam_utils::{do_call_handler, IntoPamError};
use pamsm::{Pam, PamError, PamFlags, PamResult, PamServiceModule};
use path::{PathComponent, PushPathComponent};
use std::fs::{remove_file, File};
use std::path::PathBuf;

fn user_file(dir: PathBuf, username: String) -> PathBuf {
    let mut user_data_file = dir;
    let user_file_name = PathComponent::new(username).unwrap();
    user_data_file.push_component(user_file_name);
    user_data_file
}

struct PamDirectFallback;

impl PamDirectFallback {
    fn start_session(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamResult<()> {
        let args: Args = args.try_into().pam_custom_err(PamError::IGNORE, &flags)?;

        #[cfg(feature = "sandbox")]
        Self::setup_sandbox(&args).pam_err(&flags)?;

        let username = pam_utils::get_username(&pamh, &flags)?;

        let user_data_file = user_file(args.user_store, username);

        Self::reset(user_data_file, flags)
    }

    fn auth(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamResult<()> {
        let args: Args = args.try_into().pam_custom_err(PamError::IGNORE, &flags)?;

        #[cfg(feature = "sandbox")]
        Self::setup_sandbox(&args).pam_err(&flags)?;

        let username = pam_utils::get_username(&pamh, &flags)?;

        let user_data_file = user_file(args.user_store, username);

        if args.reset {
            Self::reset(user_data_file, flags)
        } else {
            Self::set(user_data_file, flags)
        }
    }

    #[cfg(feature = "sandbox")]
    fn setup_sandbox(args: &Args) -> birdcage::error::Result<()> {
        use birdcage::{Birdcage, Sandbox};

        let mut birdcage = Birdcage::new()?;

        birdcage.add_exception(birdcage::Exception::Write(args.user_store.clone()))?;

        birdcage.lock()
    }

    fn set(user_data_file: PathBuf, flags: PamFlags) -> Result<(), PamError> {
        File::options()
            .write(true)
            .create_new(true)
            .open(user_data_file)
            .map(|_| ())
            .or_else(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => Err(PamError::AUTH_ERR),
                _ => Err(e).pam_err(&flags),
            })
    }

    fn reset(user_data_file: PathBuf, flags: PamFlags) -> Result<(), PamError> {
        remove_file(user_data_file)
            .or_else(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => Ok(()),
                _ => Err(e),
            })
            .pam_err(&flags)
    }
}

impl PamServiceModule for PamDirectFallback {
    fn open_session(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        do_call_handler(&Self::start_session, pamh, flags, args)
    }

    fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn authenticate(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        do_call_handler(&Self::auth, pamh, flags, args)
    }
}

pam_module!(PamDirectFallback);
