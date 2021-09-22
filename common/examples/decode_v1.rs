use std::env::args;

use pc_common::StoreFormatV1;

fn main() {
    let input = args().nth(1).unwrap();
    let passphrase = args().nth(2).unwrap();

    let payload = std::fs::read(input).unwrap();
    let s = StoreFormatV1::decode_from_kv(&payload, passphrase.as_bytes()).unwrap();
    println!("{}", String::from_utf8(s.as_slice().to_owned()).unwrap());
}
