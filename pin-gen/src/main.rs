mod cli;

use argon2::{password_hash, Algorithm, Argon2, Params, Version};
use clap::Parser;
use error_stack::ResultExt;
use password_hash::{rand_core::OsRng, PasswordHashString, PasswordHasher, SaltString};
use pin_data::User;
use std::time::Instant;
use sysexits::ExitCode;

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("Couldn't build sandbox")]
    Sandbox,
    #[error("Username not specified")]
    NoUsername,
    #[error("Invalid PHF parameter")]
    InvalidPhfParameter,
    #[error("Couldn't read password")]
    ReadPassword,
    #[error("Couldn't hash password")]
    HashPassword,
    #[error("Couldn't write to database")]
    WriteDatabase,
}

type Result<T> = error_stack::Result<T, Error>;

#[cfg(feature = "sandbox")]
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!(
    "Feature \"sandbox\" is not supported on the platform. Use \"--no-default-features\""
);

fn try_main() -> Result<()> {
    let args = cli::CliArgs::parse();

    #[cfg(feature = "sandbox")]
    setup_sandbox(&args)?;

    args.validate().attach(ExitCode::Usage)?;

    let argon2_params = args.argon2_params().attach(ExitCode::Usage)?;

    let pin = if args.benchmark {
        "Pin".to_string()
    } else {
        rpassword::prompt_password("Pin: ").change_context(Error::ReadPassword)?
    };

    let hashing_starting_time = Instant::now();
    let hash = hash_pin(pin, argon2_params)?;
    eprintln!(
        "Needed {}ms for hashing",
        hashing_starting_time.elapsed().as_millis()
    );

    if !args.benchmark {
        let user = User::new(args.username.unwrap(), hash);

        user.append_to_file(&args.database_filepath)
            .change_context(Error::WriteDatabase)?;
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    if let Err(report) = try_main() {
        eprintln!("Error: {:?}", report);

        if let Some(exit_code) = report.downcast_ref::<ExitCode>() {
            return (*exit_code).into();
        }

        if let Some(io_error) = report.downcast_ref::<std::io::Error>() {
            return ExitCode::from(io_error.kind()).into();
        }
        return 1.into();
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(feature = "sandbox")]
fn setup_sandbox(args: &cli::CliArgs) -> Result<()> {
    use birdcage::{Birdcage, Sandbox};

    let mut birdcage = Birdcage::new()
        .change_context(Error::Sandbox)
        .attach_printable("Initialization failed")?;

    if !args.benchmark {
        // prompt_password
        const TTY_PATH: &str = "/dev/tty";
        birdcage
            .add_exception(birdcage::Exception::Read(TTY_PATH.into()))
            .change_context(Error::Sandbox)?;
        birdcage
            .add_exception(birdcage::Exception::Write(TTY_PATH.into()))
            .change_context(Error::Sandbox)?;

        // Use the parent as the database file could be nonexistent
        let mut database_parent = args
            .database_filepath
            .parent()
            .ok_or(Error::Sandbox)
            .attach_printable("Couldn't get the parent directory of the database")?
            .to_path_buf();
        if database_parent.as_os_str().is_empty() {
            database_parent = ".".into();
        }
        birdcage
            .add_exception(birdcage::Exception::Write(database_parent))
            .change_context(Error::Sandbox)
            .attach_printable("Couldn't set the database file as writeable")?;
    }

    birdcage
        .lock()
        .change_context(Error::Sandbox)
        .attach_printable("Couldn't activate sandbox")
}

fn hash_pin(pin: String, argon2_params: Params) -> Result<PasswordHashString> {
    let argon2 = Argon2::new(Algorithm::Argon2d, Version::default(), argon2_params);

    let salt = SaltString::generate(&mut OsRng);

    argon2
        .hash_password(pin.as_bytes(), &salt)
        .map(|hash| hash.serialize())
        .change_context(Error::HashPassword)
}
