use tdx_attest::parser::Parse;
use tdx_quote::Quote;

fn main() {
    let input = std::fs::read("./examples/tdx_quote").unwrap();
    let quote = tdx_attest::Quote::parse(&input[..]).unwrap();
    let quote2 = Quote::from_bytes(&input).unwrap();
    println!("{quote:?} \n\n\n{quote2:?}");
}
