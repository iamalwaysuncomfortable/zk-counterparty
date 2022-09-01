use clap::{AppSettings, Parser, ValueEnum};

#[derive(Parser)]
#[clap(name = "Applied Cryptography Examples")]
#[clap(about = "Short Illustrative Examples of Cryptography Underlying Zero Knowledge Proofs")]
#[clap(global_setting(AppSettings::ArgRequiredElseHelp))]
pub struct ConfigArgs {
    #[clap(arg_enum, value_parser)]
    /// Which tutorial to run
    pub tutorial: Tutorials,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Tutorials {
    Merlin,
}
