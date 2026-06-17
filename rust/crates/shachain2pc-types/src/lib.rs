use core::fmt;

pub const VALUE_BYTES: usize = 32;
pub const VALUE_BITS: usize = VALUE_BYTES * 8;
pub const INDEX_BITS: u32 = 48;
pub const MAX_INDEX: u64 = (1u64 << INDEX_BITS) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Alice,
    Bob,
}

impl Role {
    pub fn from_party_id(id: u8) -> Result<Self, ParseError> {
        match id {
            1 => Ok(Self::Alice),
            2 => Ok(Self::Bob),
            _ => Err(ParseError::InvalidParty(id.to_string())),
        }
    }

    pub fn party_id(self) -> u8 {
        match self {
            Self::Alice => 1,
            Self::Bob => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Index48(u64);

impl Index48 {
    pub fn new(value: u64) -> Result<Self, ParseError> {
        if value <= MAX_INDEX {
            Ok(Self(value))
        } else {
            Err(ParseError::IndexTooLarge(value))
        }
    }

    pub fn get(self) -> u64 {
        self.0
    }

    pub fn from_hex(input: &str) -> Result<Self, ParseError> {
        let hex = input
            .strip_prefix("0x")
            .or_else(|| input.strip_prefix("0X"))
            .unwrap_or(input);
        if hex.is_empty() || hex.len() > 12 {
            return Err(ParseError::BadIndexLength(hex.len()));
        }
        let mut value = 0u64;
        for c in hex.bytes() {
            value = (value << 4) | u64::from(hex_nibble(c)?);
        }
        Self::new(value)
    }

    pub fn to_hex12(self) -> String {
        format!("{:012x}", self.0)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Value32([u8; VALUE_BYTES]);

impl Value32 {
    pub fn new(bytes: [u8; VALUE_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn zero() -> Self {
        Self([0; VALUE_BYTES])
    }

    pub fn from_hex(input: &str) -> Result<Self, ParseError> {
        if input.len() != VALUE_BYTES * 2 {
            return Err(ParseError::BadValueLength(input.len()));
        }
        let mut out = [0u8; VALUE_BYTES];
        let bytes = input.as_bytes();
        for i in 0..VALUE_BYTES {
            out[i] = (hex_nibble(bytes[2 * i])? << 4) | hex_nibble(bytes[2 * i + 1])?;
        }
        Ok(Self(out))
    }

    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(VALUE_BYTES * 2);
        for b in self.0 {
            out.push(nibble_hex(b >> 4));
            out.push(nibble_hex(b & 0x0f));
        }
        out
    }

    pub fn as_bytes(&self) -> &[u8; VALUE_BYTES] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; VALUE_BYTES] {
        self.0
    }

    pub fn xor(self, rhs: Self) -> Self {
        let mut out = [0u8; VALUE_BYTES];
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.0[i] ^ rhs.0[i];
        }
        Self(out)
    }

    pub fn to_bits_msb(self) -> Vec<u8> {
        let mut bits = vec![0; VALUE_BITS];
        for j in 0..VALUE_BYTES {
            for k in 0..8 {
                bits[8 * j + k] = (self.0[j] >> (7 - k)) & 1;
            }
        }
        bits
    }

    pub fn from_bits_msb(bits: &[u8]) -> Result<Self, ParseError> {
        if bits.len() != VALUE_BITS {
            return Err(ParseError::BadBitLength(bits.len()));
        }
        let mut out = [0u8; VALUE_BYTES];
        for j in 0..VALUE_BYTES {
            for k in 0..8 {
                out[j] |= (bits[8 * j + k] & 1) << (7 - k);
            }
        }
        Ok(Self(out))
    }
}

impl fmt::Debug for Value32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Value32").field(&self.to_hex()).finish()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParseError {
    InvalidParty(String),
    BadIndexLength(usize),
    IndexTooLarge(u64),
    BadValueLength(usize),
    BadBitLength(usize),
    BadHexChar(char),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParty(id) => write!(f, "party must be 1 or 2, got {id}"),
            Self::BadIndexLength(len) => {
                write!(f, "FromHexU48: expected 1..12 hex chars, got {len}")
            }
            Self::IndexTooLarge(value) => write!(f, "index exceeds 48 bits: {value}"),
            Self::BadValueLength(len) => {
                write!(f, "FromHex32: expected 64 hex chars, got {len}")
            }
            Self::BadBitLength(len) => write!(f, "expected 256 bits, got {len}"),
            Self::BadHexChar(c) => write!(f, "bad hex char '{c}'"),
        }
    }
}

impl std::error::Error for ParseError {}

fn hex_nibble(c: u8) -> Result<u8, ParseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ParseError::BadHexChar(char::from(c))),
    }
}

fn nibble_hex(n: u8) -> char {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    char::from(DIGITS[usize::from(n & 0x0f)])
}

#[cfg(test)]
mod tests {
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
}
