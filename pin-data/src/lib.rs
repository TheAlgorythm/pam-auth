use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    name: String,
    pin_hash: String,
}

impl User {
    pub fn new(name: impl Into<String>, pin: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pin_hash: pin.into(),
        }
    }

    pub fn pin_hash(&self) -> &str {
        &self.pin_hash
    }

    pub fn append_to_file(&self, path: &dyn AsRef<Path>) -> Result<(), IoSerdeError> {
        let data = Data {
            users: vec![self.clone()],
        };
        let data = toml::to_string(&data)?;

        let mut file = File::options().append(true).create(true).open(path)?;

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
        self.users.iter().find(|user| user.name == name)
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_data() {
        let goal = r#"[[users]]
name = "A"
pin_hash = "Pw"

[[users]]
name = "B"
pin_hash = "pw"
"#
        .to_string();

        let data = Data {
            users: vec![User::new("A", "Pw"), User::new("B", "pw")],
        };

        let toml = toml::to_string(&data).unwrap();

        assert_eq!(toml, goal);
    }
}
