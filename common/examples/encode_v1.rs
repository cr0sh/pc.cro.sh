use std::env::args;

use pc_common::{into_utf8, StoreFormatV1};

fn main() {
    let input = args().nth(1).unwrap();
    let output = args().nth(2).unwrap();
    let passphrase = args().nth(3).unwrap();

    let payload = std::fs::read(input).unwrap();
    let payload = into_utf8(payload).unwrap();
    println!("input: {}", String::from_utf8(payload.clone()).unwrap());
    println!("Input size: {} bytes", payload.len());

    let contents = StoreFormatV1::new(payload)
        .encode_to_kv(passphrase.as_bytes())
        .unwrap();

    println!("Output size: {} bytes", contents.len());

    std::fs::write(output, contents).unwrap();
}
