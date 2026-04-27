use error_stack::ResultExt;
use pamsm::{Pam, PamError, PamFlags, PamLibExt};

type ResultReport<T, E> = Result<T, error_stack::Report<E>>;

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

pub fn do_call_handler<C, F>(
    handler: F,
    mut pamh: Pam,
    flags: PamFlags,
    args: Vec<String>,
    sandbox_panic_error: C,
) -> PamError
where
    C: std::error::Error + Send + Sync + 'static,
    F: Fn(&Pam, PamFlags, Vec<String>) -> ResultReport<(), C> + Send,
{
    let is_debug = is_debug(&args);

    #[cfg(not(feature = "sandbox"))]
    let res = handler(&pamh, flags, args);

    #[cfg(feature = "sandbox")]
    let res = do_threaded_call(&mut pamh, handler, flags, args, sandbox_panic_error);

    if let Err(error_context) = res {
        print_error(&error_context, &pamh, flags, is_debug);

        return error_context
            .downcast_ref::<PamError>()
            .copied()
            .unwrap_or(PamError::AUTH_ERR);
    }
    PamError::SUCCESS
}

#[cfg(feature = "sandbox")]
fn do_threaded_call<C, F>(
    pamh: &mut Pam,
    handler: F,
    flags: PamFlags,
    args: Vec<String>,
    sandbox_panic_error: C,
) -> ResultReport<(), C>
where
    C: std::error::Error + Send + Sync + 'static,
    F: Fn(&Pam, PamFlags, Vec<String>) -> ResultReport<(), C> + Send,
{
    std::thread::scope(|scope| {
        let moving_handle = pamh.as_send_ref();
        let sandbox_thread = scope.spawn(move || handler(&moving_handle, flags, args));
        sandbox_thread
            .join()
            .map_err(|_thread_err| error_stack::Report::new(sandbox_panic_error))
    })?
}

fn print_error<C>(
    error_context: &error_stack::Report<C>,
    pamh: &Pam,
    flags: PamFlags,
    is_debug: bool,
) where
    C: std::error::Error,
{
    if !flags.contains(PamFlags::SILENT) {
        let error_message = if is_debug {
            format!("Error: {error_context:?}")
        } else {
            format!("Error: {error_context}")
        };
        let print_error = "Couldn't print error message";
        let input = pamh
            .conv(Some(&error_message), pamsm::PamMsgStyle::ERROR_MSG)
            .expect(print_error);
        assert!(input.is_none(), "{print_error} correctly");
    }
}

#[must_use]
pub fn extract_named_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .find(|arg| arg.starts_with(key))
        .map(|value| value.trim_start_matches(key))
}

const DEBUG_ID: &str = "debug";

#[must_use]
pub fn is_debug(args: &[String]) -> bool {
    args.contains(&DEBUG_ID.to_owned())
}

pub fn get_username<E: std::error::Error + Send + Sync + Clone + 'static>(
    pamh: &Pam,
    pam_error: E,
    unknown_user_error: E,
) -> ResultReport<String, E> {
    pamh.get_user(None)
        .map_err(|pam_code| error_stack::Report::new(pam_error).attach_opaque(pam_code))?
        .ok_or(unknown_user_error.clone())
        .attach_opaque(PamError::USER_UNKNOWN)?
        .to_str()
        .map(str::to_owned)
        .change_context(unknown_user_error)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
