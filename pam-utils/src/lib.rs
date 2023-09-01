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

#[cfg(feature = "sandbox")]
#[cfg(not(target_os = "linux"))]
compile_error!(
    "Feature \"sandbox\" is not supported on the platform. Use \"--no-default-features\""
);

pub fn do_call_handler<F: Fn(&Pam, PamFlags, Vec<String>) -> Result<(), PamError> + Send>(
    handler: F,
    pamh: Pam,
    flags: PamFlags,
    args: Vec<String>,
) -> PamError {
    #[cfg(not(feature = "sandbox"))]
    let res = handler(&pamh, flags, args);
    #[cfg(feature = "sandbox")]
    let res = do_threaded_call(pamh, handler, flags, args);
    err_try!(res);
    PamError::SUCCESS
}

#[cfg(feature = "sandbox")]
fn do_threaded_call<F: Fn(&Pam, PamFlags, Vec<String>) -> Result<(), PamError> + Send>(
    mut pamh: Pam,
    handler: F,
    flags: PamFlags,
    args: Vec<String>,
) -> Result<(), PamError> {
    std::thread::scope(|scope| {
        let moving_handle = pamh.as_send_ref();
        let sandbox_thread = scope.spawn(move || handler(&moving_handle, flags, args));
        sandbox_thread
            .join()
            .map_err(|_| "A panic happened in the sandboxed thread")
            .pam_err(&flags)
    })?
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
