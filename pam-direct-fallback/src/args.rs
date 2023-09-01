use std::path::PathBuf;

pub struct Args {
    pub user_store: PathBuf,
    pub reset: bool,
}

impl Args {
    const USER_STORE_ID: &'static str = "store=";
    const USER_STORE_MISSING: &'static str = "There is no `store=/<dir>` given.";
    const RESET_ID: &'static str = "reset";
}

impl TryFrom<Vec<String>> for Args {
    type Error = &'static str;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let user_store = pam_utils::extract_named_value(&value, Self::USER_STORE_ID)
            .ok_or(Self::USER_STORE_MISSING)?
            .into();
        let reset = value.contains(&Self::RESET_ID.to_string());

        Ok(Self { user_store, reset })
    }
}
