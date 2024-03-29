use argon2::password_hash::{PasswordHash, PasswordHashString};
use error_stack::ResultExt;
use serde::{Deserialize, Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
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

    pub fn append_to_file(&self, path: &dyn AsRef<Path>) -> error_stack::Result<(), IoSerdeError> {
        let data = Data {
            users: vec![self.clone()],
        };
        let data = toml::to_string(&data).change_context(IoSerdeError::Serialize)?;

        let mut file_options = File::options();
        file_options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file_options.mode(0o600);
        }

        let write_error = || IoSerdeError::Write(path.as_ref().to_path_buf());

        let mut file = file_options.open(path).change_context_lazy(write_error)?;

        let is_created = file
            .metadata()
            .change_context(IoSerdeError::Read(path.as_ref().to_path_buf()))?
            .len()
            == 0;

        if is_created {
            file.write_all(data.as_bytes())
                .change_context_lazy(write_error)?;
        } else {
            write!(file, "\n{}", data).change_context_lazy(write_error)?;
        }
        file.flush().change_context_lazy(write_error)?;

        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Data {
    users: Vec<User>,
}

impl Data {
    pub fn from_file(path: &dyn AsRef<Path>) -> error_stack::Result<Self, IoSerdeError> {
        let data_string = std::fs::read_to_string(path)
            .change_context(IoSerdeError::Read(path.as_ref().to_path_buf()))?;
        toml::from_str(&data_string).change_context(IoSerdeError::Deserialize)
    }

    pub fn get_by_name<'a>(&'a self, name: &str) -> Option<&'a User> {
        self.users.iter().rev().find(|user| user.name == name)
    }
}

#[derive(Error, Debug)]
pub enum IoSerdeError {
    #[error("Couldn't write to file '{}'", .0.display())]
    Write(PathBuf),
    #[error("Couldn't read from file '{}'", .0.display())]
    Read(PathBuf),
    #[error("Couldn't serialize structure")]
    Serialize,
    #[error("Couldn't deserialize file")]
    Deserialize,
}
