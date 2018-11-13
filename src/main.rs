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
                    .long("numprocesses")
                    .help("the number of worker processes to generate")
                    .takes_value(true)
                    .default_value("1")),
        ).get_matches();

    if let Some(matches) = matches.subcommand_matches("solve") {
        let base_string = matches
            .value_of("base string")
            .expect("Expected a base string");
        let base = base_string.as_bytes().to_vec();
        let target_hash =
            value_t!(matches, "target hash", Sha256Hash).expect("Invalid 256 bit hex");
        let num_workers = value_t!(matches, "number of processes", u8)
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
}
