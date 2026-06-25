use sev::parser::ByteParser;

fn main() {
    let report = sev::firmware::guest::AttestationReport::from_bytes(
        &std::fs::read(std::env::args().nth(1).unwrap()).unwrap(),
    );
    println!("{:?}", report);
}
