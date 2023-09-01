mod cli;

use argon2::{password_hash, Algorithm, Argon2, Params, Version};
use clap::Parser;
use password_hash::{rand_core::OsRng, PasswordHashString, PasswordHasher, SaltString};
use pin_data::User;
use rpassword::prompt_password;
use std::time::Instant;

macro_rules! eprint_try {
    ($res:expr) => {
        match $res {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Error: {}", e);
                return;
            }
        }
    };
}

fn hash_pin(
    pin: String,
    argon2_params: Params,
) -> password_hash::errors::Result<PasswordHashString> {
    let argon2 = Argon2::new(Algorithm::Argon2d, Version::default(), argon2_params);

    let salt = SaltString::generate(&mut OsRng);

    argon2
        .hash_password(pin.as_bytes(), &salt)
        .map(|hash| hash.serialize())
}

#[cfg(feature = "sandbox")]
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!(
    "Feature \"sandbox\" is not supported on the platform. Use \"--no-default-features\""
);

#[cfg(feature = "sandbox")]
fn setup_sandbox(args: &cli::CliArgs) -> birdcage::error::Result<()> {
    use birdcage::{Birdcage, Sandbox};

    let mut birdcage = Birdcage::new()?;

    if !args.benchmark {
        // prompt_password
        const TTY_PATH: &str = "/dev/tty";
        birdcage.add_exception(birdcage::Exception::Read(TTY_PATH.into()))?;
        birdcage.add_exception(birdcage::Exception::Write(TTY_PATH.into()))?;

        // Use the parent as the database file could be nonexistent
        let mut database_parent = args
            .database_filepath
            .parent()
            .expect("Couldn't get the parent directory of the database")
            .to_path_buf();
        if database_parent.as_os_str().is_empty() {
            database_parent = ".".into();
        }
        birdcage.add_exception(birdcage::Exception::Write(database_parent))?;
    }

    birdcage.lock()
}

fn main() {
    let args = cli::CliArgs::parse();

    #[cfg(feature = "sandbox")]
    eprint_try!(setup_sandbox(&args));

    eprint_try!(args.validate());

    let argon2_params = eprint_try!(args.argon2_params());

    let pin = if args.benchmark {
        "Pin".to_string()
    } else {
        eprint_try!(prompt_password("Pin: "))
    };

    let hashing_starting_time = Instant::now();
    let hash = eprint_try!(hash_pin(pin, argon2_params));
    eprintln!(
        "Needed {}ms for hashing",
        hashing_starting_time.elapsed().as_millis()
    );

    if !args.benchmark {
        let user = User::new(args.username.unwrap(), hash);

        eprint_try!(user.append_to_file(&args.database_filepath));
    }
}
