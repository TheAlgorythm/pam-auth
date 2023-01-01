#[macro_use]
extern crate pamsm;
#[macro_use]
extern crate pam_utils;

use pam_utils::IntoPamError;
use pamsm::{Pam, PamError, PamFlags, PamResult, PamServiceModule};
use std::fs::{remove_file, File};
use std::path::PathBuf;

struct Args {
    pub user_store: PathBuf,
    pub reset: bool,
}

impl Args {
    const USER_STORE_ID: &'static str = "store=";
    const USER_STORE_MISSING: &'static str = "There is no `store=/<dir>` given.";
    const RESET_ID: &'static str = "reset";
}

impl TryFrom<Vec<String>> for Args {
    type Error = &'static str;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let user_store = pam_utils::extract_named_value(&value, Self::USER_STORE_ID)
            .ok_or(Self::USER_STORE_MISSING)?
            .into();
        let reset = value.contains(&Self::RESET_ID.to_string());

        Ok(Self { user_store, reset })
    }
}

struct PathComponent {
    path: PathBuf,
}

impl PathComponent {
    pub fn new<S: Into<PathBuf>>(component: S) -> Option<Self> {
        let component = Self {
            path: component.into(),
        };

        component.is_valid().then_some(component)
    }

    fn is_valid(&self) -> bool {
        use std::path::Component;

        let mut components = self.path.components();
        matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(_)), None)
        )
    }
}

impl AsRef<std::path::Path> for PathComponent {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

trait PushPathComponent {
    fn push_component(&mut self, component: PathComponent);
}

impl PushPathComponent for PathBuf {
    fn push_component(&mut self, component: PathComponent) {
        self.push(component);
    }
}

fn user_file(dir: PathBuf, username: String) -> PathBuf {
    let mut user_data_file = dir;
    // TODO Prevent dir traversal attack
    let user_file_name = PathComponent::new(username).unwrap();
    user_data_file.push_component(user_file_name);
    user_data_file
}

struct PamDirectFallback;

impl PamDirectFallback {
    fn start_session(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamResult<()> {
        let args: Args = args.try_into().pam_custom_err(PamError::IGNORE, &flags)?;

        let username = pam_utils::get_username(&pamh, &flags)?;

        let user_data_file = user_file(args.user_store, username);

        Self::reset(user_data_file, flags)
    }

    fn auth(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamResult<()> {
        let args: Args = args.try_into().pam_custom_err(PamError::IGNORE, &flags)?;

        let username = pam_utils::get_username(&pamh, &flags)?;

        let user_data_file = user_file(args.user_store, username);

        if args.reset {
            Self::reset(user_data_file, flags)
        } else {
            Self::set(user_data_file, flags)
        }
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
        err_try!(Self::start_session(pamh, flags, args));
        PamError::SUCCESS
    }

    fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn authenticate(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        err_try!(Self::auth(pamh, flags, args));
        PamError::SUCCESS
    }
}

pam_module!(PamDirectFallback);

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
