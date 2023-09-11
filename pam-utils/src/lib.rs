use error_stack::ResultExt;
use pamsm::{Pam, PamError, PamFlags, PamLibExt};

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
    pamh: Pam,
    flags: PamFlags,
    args: Vec<String>,
    sandbox_panic_error: C,
) -> PamError
where
    C: error_stack::Context,
    F: Fn(&Pam, PamFlags, Vec<String>) -> error_stack::Result<(), C> + Send,
{
    #[cfg(not(feature = "sandbox"))]
    let res = handler(&pamh, flags, args);
    #[cfg(feature = "sandbox")]
    let res = do_threaded_call(pamh, handler, flags, args, sandbox_panic_error);
    if let Err(error_context) = res {
        if !flags.contains(PamFlags::SILENT) {
            println!("Error: {:?}", error_context);
        }

        return error_context
            .downcast_ref::<PamError>()
            .map(Clone::clone)
            .unwrap_or(PamError::AUTH_ERR);
    }
    PamError::SUCCESS
}

#[cfg(feature = "sandbox")]
fn do_threaded_call<C, F>(
    mut pamh: Pam,
    handler: F,
    flags: PamFlags,
    args: Vec<String>,
    sandbox_panic_error: C,
) -> error_stack::Result<(), C>
where
    C: error_stack::Context,
    F: Fn(&Pam, PamFlags, Vec<String>) -> error_stack::Result<(), C> + Send,
{
    std::thread::scope(|scope| {
        let moving_handle = pamh.as_send_ref();
        let sandbox_thread = scope.spawn(move || handler(&moving_handle, flags, args));
        sandbox_thread
            .join()
            .map_err(|_| error_stack::Report::new(sandbox_panic_error))
        // .map_err(|_| "A panic happened in the sandboxed thread")
        // .pam_err(&flags)
    })?
}

pub fn extract_named_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .find(|arg| arg.starts_with(key))
        .map(|value| value.trim_start_matches(key))
}

pub fn get_username<E: error_stack::Context + Clone>(
    pamh: &Pam,
    pam_error: E,
    unknown_user_error: E,
) -> error_stack::Result<String, E> {
    pamh.get_user(None)
        .map_err(|pam_code| error_stack::Report::new(pam_error).attach(pam_code))?
        .ok_or(unknown_user_error.clone())
        .attach(PamError::USER_UNKNOWN)?
        .to_str()
        .map(ToString::to_string)
        .change_context(unknown_user_error)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
