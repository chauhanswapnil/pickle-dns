pub fn bytes_to_hex(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("0x{:02x}", b)).collect()
}
