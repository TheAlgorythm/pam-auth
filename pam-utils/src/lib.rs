use pamsm::{Pam, PamError, PamFlags, PamLibExt};
use std::fmt::Display;

#[macro_export]
macro_rules! err_try {
    ($res:expr) => {
        match $res {
            Ok(res) => res,
            Err(e) => return e,
        }
    };
}

pub trait IntoPamError<T> {
    fn pam_err(self, flags: &PamFlags) -> Result<T, PamError>
    where
        Self: Sized,
    {
        self.pam_custom_err(PamError::AUTH_ERR, flags)
    }
    fn pam_custom_err(self, custom_error: PamError, flags: &PamFlags) -> Result<T, PamError>;
}

impl<T, E: Display> IntoPamError<T> for Result<T, E> {
    fn pam_custom_err(self, custom_error: PamError, flags: &PamFlags) -> Result<T, PamError> {
        self.map_err(|error| {
            if !flags.contains(PamFlags::SILENT) {
                println!("Error: {}", error);
            }
            custom_error
        })
    }
}

pub fn extract_named_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .find(|arg| arg.starts_with(key))
        .map(|value| value.trim_start_matches(key))
}

pub fn get_username(pamh: &Pam, flags: &PamFlags) -> Result<String, PamError> {
    pamh.get_user(None)?
        .ok_or(PamError::USER_UNKNOWN)?
        .to_str()
        .map(ToString::to_string)
        .pam_err(flags)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
