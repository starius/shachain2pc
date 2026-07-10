use super::*;

#[test]
fn parses_index_like_cpp() {
    assert_eq!(Index48::from_hex("0").unwrap().get(), 0);
    assert_eq!(Index48::from_hex("0x1").unwrap().get(), 1);
    assert_eq!(Index48::from_hex("ffffffffffff").unwrap().get(), MAX_INDEX);
    assert!(Index48::from_hex("").is_err());
    assert!(Index48::from_hex("1000000000000").is_err());
}

#[test]
fn value_hex_round_trip() {
    let s = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let v = Value32::from_hex(s).unwrap();
    assert_eq!(v.to_hex(), s);
    assert_eq!(Value32::from_bits_msb(&v.to_bits_msb()).unwrap(), v);
}
