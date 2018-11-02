mod lib;
use lib::HashWorkerFarm;
use lib::Sha256Hash;
use std::time::Instant;

fn main() {
    let start_time = Instant::now();
    let base = b"ErAs=``?2M>^lm_8jx_TK9y_^0fL`".to_vec();
    let target_hash = Sha256Hash::from_hex_string(
        &"000000ffffff0000000000000000000000000000000000000000000000000000".to_string(),
    ).expect("Invalid 256 bit hex");
    let hash_farm = HashWorkerFarm::new(base, target_hash.clone(), /* num workers */ 4);
    let result = hash_farm.solve();
    match result {
        Some(result) => println!(
            "Solved with nonce: {}, hash: {}\nTarget: {}\nTime (s): {}",
            result.nonce,
            result.hash,
            target_hash,
            start_time.elapsed().as_secs()
        ),
        None => println!("No solution found"),
    }
}
