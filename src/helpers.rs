use crate::errors::ParseError;

pub fn bytes_to_hex(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("0x{:02x}", b)).collect()
}

pub fn bytes_to_u16_array(bytes: &[u8]) -> Result<Vec<u16>, ParseError> {
    if bytes.len() % 2 != 0 || bytes.len() < 2 {
        return Err(ParseError::InvalidByteLength);
    }
    let mut u16_array = Vec::with_capacity(bytes.len() / 2);

    for chunk in bytes.chunks(2) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        u16_array.push(value);
    }
    Ok(u16_array)
}
