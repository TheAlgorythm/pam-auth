use std::path::PathBuf;

pub(crate) struct Args {
    pub database_filepath: PathBuf,
}

impl Args {
    const DATABASE_FILEPATH_ID: &'static str = "db=";
}

impl TryFrom<Vec<String>> for Args {
    type Error = crate::Error;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let database_filepath = pam_utils::extract_named_value(&value, Self::DATABASE_FILEPATH_ID)
            .ok_or(crate::Error::MissingDatabaseArg)?
            .into();

        Ok(Self { database_filepath })
    }
}
