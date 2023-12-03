use crate::{Error, Result};
use clap::Parser;
use error_stack::ResultExt;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about)]
pub struct CliArgs {
    #[clap(short = 'f', long, default_value = "/etc/security/pins.toml")]
    pub database_filepath: PathBuf,
    #[clap(env = "SUDO_USER")]
    pub username: Option<String>,
    /// Use this flag to try different parameters.
    /// It disables the need for a username and pin.
    #[clap(short, long)]
    pub benchmark: bool,
    /// For Argon2.
    /// Try to use in the range of 65536 KiB and available memory / 2.
    /// The unit is KiB.
    #[clap(short, long)]
    pub memory_cost: Option<u32>,
    /// For Argon2.
    /// Optimize for a few hundred milliseconds.
    #[clap(short, long)]
    pub time_cost: Option<u32>,
    /// For Argon2.
    /// Use the number of physical threads.
    #[clap(short, long)]
    pub parallelism: Option<u32>,
}

impl CliArgs {
    pub fn validate(&self) -> Result<()> {
        (self.benchmark || self.username.is_some())
            .then_some(())
            .ok_or(Error::NoUsername.into())
    }

    pub fn argon2_params(&self) -> Result<argon2::Params> {
        let mut argon2_params = argon2::ParamsBuilder::new();

        if let Some(memory_cost) = self.memory_cost {
            argon2_params.m_cost(memory_cost);
        }
        if let Some(time_cost) = self.time_cost {
            argon2_params.t_cost(time_cost);
        }
        if let Some(parallelism) = self.parallelism {
            argon2_params.p_cost(parallelism);
        }

        argon2_params
            .build()
            .change_context(Error::InvalidPhfParameter)
    }
}
