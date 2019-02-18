use {
    structopt::StructOpt,
    std::{
        path::{PathBuf},
    },
};

#[derive(StructOpt)]
#[structopt(name="rkasm")]
struct RkasmArg {
    #[structopt(
        name = "file",
        short = "f",
        long = "file",
        parse(from_os_str),
        help = "Assembly file"
    )]
    file_path: PathBuf
}