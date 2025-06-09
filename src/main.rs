use clap::Parser;
use wldd_rs::{run, Config};
use std::process;

fn main() {
    if let Err(e) = run(Config::parse()) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
