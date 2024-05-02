use cargo_autoinherit::{auto_inherit, uninherit};

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(bin_name = "cargo")]
struct CliWrapper {
    #[command(subcommand)]
    command: CargoInvocation,
}

#[derive(Parser)]
enum CargoInvocation {
    /// Automatically centralize all dependencies as workspace dependencies.
    #[command(name = "autoinherit")]
    AutoInherit(AutoInheritArgs),
}

#[derive(Subcommand)]
enum Subcommands {
    /// Insert the workspace-version locally into those packages.
    Uninherit(UninheritArgs),
}

#[derive(Args)]
struct UninheritArgs {
    /// Names of packages to uninherit
    packages: Vec<String>,
}

#[derive(Args)]
struct AutoInheritArgs {
    #[command(subcommand)]
    uninherit: Option<Subcommands>,

    /// Package name(s) of workspace member(s) to exclude.
    #[arg(short, long)]
    exclude: Vec<String>,

    /// No changes but exit code 1 if anything would be changed or any dependencies could not be inherited.
    #[arg(short, long, action)]
    dry_run: bool,
}

fn main() -> Result<(), anyhow::Error> {
    let cli = CliWrapper::parse();

    match cli.command {
        CargoInvocation::AutoInherit(args) => match args.uninherit {
            None => {
                let code = auto_inherit(args.exclude, args.dry_run)?;
                if code != 0 {
                    std::process::exit(code);
                } else {
                    Ok(())
                }
            }
            Some(Subcommands::Uninherit(args)) => uninherit(args.packages),
        },
    }
}
