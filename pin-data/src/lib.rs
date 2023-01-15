use argon2::password_hash::{PasswordHash, PasswordHashString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    name: String,
    #[serde(serialize_with = "as_str", deserialize_with = "hash_from_str")]
    pin_hash: PasswordHashString,
}

fn hash_from_str<'de, D>(deserializer: D) -> Result<PasswordHashString, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let hash = String::deserialize(deserializer)?;

    PasswordHashString::new(&hash).map_err(|error| Error::custom(error.to_string()))
}

fn as_str<T, S>(v: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<str>,
    S: Serializer,
{
    serializer.serialize_str(v.as_ref())
}

impl User {
    pub fn new(name: impl Into<String>, pin: PasswordHashString) -> Self {
        Self {
            name: name.into(),
            pin_hash: pin,
        }
    }

    pub fn pin_hash(&self) -> PasswordHash<'_> {
        self.pin_hash.password_hash()
    }

    pub fn append_to_file(&self, path: &dyn AsRef<Path>) -> Result<(), IoSerdeError> {
        let data = Data {
            users: vec![self.clone()],
        };
        let data = toml::to_string(&data)?;

        let mut file_options = File::options();
        file_options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file_options.mode(0o600);
        }

        let mut file = file_options.open(path)?;

        let is_created = file.metadata()?.len() == 0;

        if is_created {
            file.write_all(data.as_bytes())?;
        } else {
            write!(file, "\n{}", data)?;
        }
        file.flush()?;

        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Data {
    users: Vec<User>,
}

impl Data {
    pub fn from_file(path: &dyn AsRef<Path>) -> Result<Self, IoSerdeError> {
        let data_string = std::fs::read_to_string(path)?;
        toml::from_str(&data_string).map_err(IoSerdeError::Deserialize)
    }

    pub fn get_by_name<'a>(&'a self, name: &str) -> Option<&'a User> {
        self.users.iter().rev().find(|user| user.name == name)
    }
}

#[derive(Error, Debug)]
pub enum IoSerdeError {
    #[error(transparent)]
    Read(#[from] std::io::Error),
    #[error(transparent)]
    Serialize(#[from] toml::ser::Error),
    #[error(transparent)]
    Deserialize(#[from] toml::de::Error),
}
