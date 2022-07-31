use argon2::{password_hash, Algorithm, Argon2, Params, Version};
use password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
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

fn hash_pin(pin: String) -> password_hash::errors::Result<String> {
    let argon2 = Argon2::new(Algorithm::Argon2d, Version::default(), Params::default());

    let salt = SaltString::generate(&mut OsRng);

    argon2
        .hash_password(pin.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}

fn main() {
    let pin = eprint_try!(prompt_password("Pin: "));

    let hashing_starting_time = Instant::now();
    let hash = eprint_try!(hash_pin(pin));
    eprintln!(
        "Needed {}ms for hashing",
        hashing_starting_time.elapsed().as_millis()
    );

    let user = User::new("zschoen", hash);

    eprint_try!(user.append_to_file(&"/etc/security/pins.toml"));
}
