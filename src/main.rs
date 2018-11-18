#[macro_use]
extern crate clap;

mod lib;
use clap::{App, Arg, SubCommand};
use lib::HashWorkerFarm;
use lib::Sha256Hash;
use lib::TNonce;
use std::time::Instant;

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
                .about("generates a target hash given an amount of time to solve it and a hash rate")                .arg(
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
        .get_matches();

    match matches.subcommand() {
        ("solve", Some(solve_matches)) => {
            let base_string = solve_matches
                .value_of("base string")
                .expect("Expected a base string");
            let base = base_string.as_bytes().to_vec();
            let target_hash =
                value_t!(solve_matches, "target hash", Sha256Hash).expect("Invalid 256 bit hex");
            let num_workers = value_t!(solve_matches, "number of processes", u8)
                .expect("Invalid number of worker processes");
            let hash_farm = HashWorkerFarm::new(base, target_hash.clone(), num_workers);
            let start_time = Instant::now();
            let result = hash_farm.solve();
            match result {
                Some(result) => println!(
                    "Base string: {},\nSolved with nonce: {},\nAs bytes: {},\nHash: {}\nTarget: {}\nTime (s): {}",
                    base_string,
                    result.nonce,
                    result.nonce.as_hex_bytes(),
                    result.hash,
                    target_hash,
                    start_time.elapsed().as_secs()
                ),
                None => println!("No solution found"),
            }
        }
        ("make_target", Some(make_target_matches)) => {
            let duration_string = make_target_matches
                .value_of("duration")
                .expect("Expected a valid duration string");
            let hash_rate = value_t!(make_target_matches, "hashrate", u64)
                .expect("Expected a valid integer hashrate");
            let result = Sha256Hash::target_for_duration(duration_string.to_string(), hash_rate);
            println!("{}", result);
        }
        ("hashrate_test", Some(hashrate_test_matches)) => {
            let num_workers = value_t!(hashrate_test_matches, "number of processes", u8)
                .expect("Invalid number of worker processes");
            let length =
                value_t!(hashrate_test_matches, "length", u64).expect("Invalid test time length");
            let test_hash_farm = HashWorkerFarm::new_test(num_workers);
            println!(
                "Running test for {} seconds with {} processes",
                length, num_workers
            );
            println!("{}", test_hash_farm.run_test(length));
        }
        ("", None) => println!("No subcommand was used, try \"help\""),
        _ => unreachable!(), // Assuming you've listed all direct children above, this is unreachable
    }
}
