use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;

mod config;
mod core;
mod storage;
mod commands;

#[derive(Parser)]
struct Opt {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Start { iface: String },
    Stop,
    Status,
    Log,
    Block { ip: Ipv4Addr },
    Unblock { ip: Ipv4Addr },
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    match opt.command {
        Command::Start { iface } => commands::start::run(iface).await,
        Command::Stop => commands::stop::run().await,
        Command::Status => commands::status::run().await,
        Command::Log => core::logger::run().await,
        Command::Block { ip } => commands::block::run(ip).await,
        Command::Unblock { ip } => commands::unblock::run(ip).await,
        Command::List => commands::list::run().await,
    }
}