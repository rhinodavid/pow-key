mod lib;
use lib::Sha256Hash;
use lib::Sha256Hasher;

fn main() {
    let hasher = Sha256Hasher::new(b"ErAs=``?2M>^Nfrlm_8jx_TK9y_^0fL`");
    let target_hash = Sha256Hash {
        value: [
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
    };
    // println!("{}", target_hash.to_hex());
    let mut nonce = 0;
    while nonce < std::u32::MAX - 1 {
        let result_hash = hasher.hash_with_nonce(nonce);
        if result_hash < target_hash {
            println!(
                "Found solution with nonce: {}\nTarget: {}\nResult:{}",
                nonce,
                target_hash.to_hex(),
                result_hash.to_hex()
            );
            return;
        }
        println!("{}: {}", nonce, result_hash.to_hex());
        nonce = nonce + 1;
    }
    println!("No solution found");
}
