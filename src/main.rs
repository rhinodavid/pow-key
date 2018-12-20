mod cli;
mod hash;
mod net;

use crate::hash::Sha256Hash;
use crate::net::PowServer;
use clap::{value_t, App, Arg, SubCommand};

fn main() {
    let matches = App::new("POW Key")
        .version(env!("CARGO_PKG_VERSION"))
        .author("David Walsh <dawalsh@gmail.com>")
        .about("The Proof of Work lock companion app")
        .subcommand(
            SubCommand::with_name("solve")
                .about("finds a nonce that will unlock the device")
                .arg(
                    Arg::with_name("base string")
                        .short("b")
                        .long("base")
                        .help("the ascii string generated by the device when it was locked")
                        .takes_value(true)
                        .required(true))
                .arg(
                    Arg::with_name("target hash")
                        .short("t")
                        .long("target")
                        .help("the hex representation of the sha256 hash the solution hash must be less than")
                        .takes_value(true)
                        .required(true))
                .arg(
                    Arg::with_name("number of processes")
                    .short("p")
                    .long("num_processes")
                    .help("the number of worker processes to generate")
                    .takes_value(true)
                    .default_value("1")))
        .subcommand(
            SubCommand::with_name("make_target")
                .about("generates a target hash given an amount of time to solve it and a hash rate")
                .arg(
                    Arg::with_name("duration")
                        .short("d")
                        .long("duration")
                        .help("a plain text description of how long it should take to solve, ex: 4hr 25min")
                        .takes_value(true)
                        .required(true))
                .arg(
                    Arg::with_name("hashrate")
                        .short("r")
                        .long("hashrate")
                        .help("the hashrate in hashes per second")
                        .takes_value(true)
                        .required(true)))
        .subcommand(
            SubCommand::with_name("hashrate_test")
                .about("runs a short test to estimate the hashrate you can expect from this machine")
                .arg(
                    Arg::with_name("length")
                    .short("l")
                    .long("length")
                    .help("the length of time to run the test in seconds")
                    .takes_value(true)
                    .default_value("30"))
                .arg(
                    Arg::with_name("number of processes")
                    .short("p")
                    .long("num_processes")
                    .help("the number of worker processes to generate")
                    .takes_value(true)
                    .default_value("1")))
            .subcommand(SubCommand::with_name("device")
                .about("interacts with a POW lock over the network")
                .setting(clap::AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("open")
                        .about("opens an unlocked lock")
                        .arg(Arg::with_name("hostname")
                            .short("h")
                            .long("hostname")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("port")
                            .short("p")
                            .long("port")
                            .takes_value(true)
                            .required(true)))
                .subcommand(
                    SubCommand::with_name("status")
                        .about("gets the status (unlocked or locked) of a device")
                        .arg(Arg::with_name("hostname")
                            .short("h")
                            .long("hostname")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("port")
                            .short("p")
                            .long("port")
                            .takes_value(true)
                            .required(true)))
                .subcommand(
                    SubCommand::with_name("base")
                        .about("gets the base string of a lock that is locked")
                        .arg(Arg::with_name("hostname")
                            .short("h")
                            .long("hostname")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("port")
                            .short("p")
                            .long("port")
                            .takes_value(true)
                            .required(true)))
                .subcommand(
                    SubCommand::with_name("target")
                        .about("gets the target hash of a locked device in hex")
                        .arg(Arg::with_name("hostname")
                            .short("h")
                            .long("hostname")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("port")
                            .short("p")
                            .long("port")
                            .takes_value(true)
                            .required(true)))
                .subcommand(
                    SubCommand::with_name("lock")
                        .about("locks a device and sets the target hash")
                        .arg(Arg::with_name("hostname")
                            .short("h")
                            .long("hostname")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("port")
                            .short("p")
                            .long("port")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("target")
                            .short("t")
                            .long("target")
                            .takes_value(true)
                            .required(true)))
                .subcommand(
                    SubCommand::with_name("unlock")
                        .about("attempts to unlock a device given a u64 integer nonce")
                        .arg(Arg::with_name("hostname")
                            .short("h")
                            .long("hostname")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("port")
                            .short("p")
                            .long("port")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("nonce")
                            .short("n")
                            .long("nonce")
                            .takes_value(true)
                            .required(true)))
            )
        .get_matches();

    match matches.subcommand() {
        ("solve", Some(solve_matches)) => {
            let base_string = solve_matches
                .value_of("base string")
                .expect("Expected a base string");
            let target_hash =
                value_t!(solve_matches, "target hash", Sha256Hash).expect("Invalid 256 bit hex");
            let num_workers = value_t!(solve_matches, "number of processes", u8)
                .expect("Invalid number of worker processes");
            cli::solve(base_string.to_string(), target_hash, num_workers);
        }
        ("make_target", Some(make_target_matches)) => {
            let duration_string = make_target_matches
                .value_of("duration")
                .expect("Expected a valid duration string");
            let hash_rate = value_t!(make_target_matches, "hashrate", u64)
                .expect("Expected a valid integer hashrate");
            cli::make_target(duration_string.to_string(), hash_rate);
        }
        ("hashrate_test", Some(hashrate_test_matches)) => {
            let num_workers = value_t!(hashrate_test_matches, "number of processes", u8)
                .expect("Invalid number of worker processes");
            let length =
                value_t!(hashrate_test_matches, "length", u64).expect("Invalid test time length");
            cli::hashrate_test(num_workers, length);
        }
        ("device", Some(device_matches)) => {
            let host = value_t!(device_matches, "hostname", String).expect("Invalid host");
            let port = value_t!(device_matches, "port", String).expect("Invalid port");
            let server = PowServer::new(host, port);
            match device_matches.subcommand() {
                ("status", _) => cli::get_status(server),
                ("unlock", Some(unlock_matches)) => {
                    let nonce = value_t!(unlock_matches, "nonce", u64).expect("Invalid nonce");
                    cli::unlock(server, nonce);
                }
                ("open", _) => cli::open(server),
                ("base", _) => cli::base(server),
                ("target", _) => cli::target(server),
                ("lock", Some(lock_matches)) => {
                    let target = value_t!(lock_matches, "target", String).expect("Invalid port");
                    cli::lock(server, target);
                }
                ("", None) => println!("No subcommand was used, try \"help\""),
                _ => unreachable!(), // Assuming you've listed all direct children above, this is unreachable
            }
        }
        ("", None) => println!("No subcommand was used, try \"help\""),
        _ => unreachable!(), // Assuming you've listed all direct children above, this is unreachable
    }
}
