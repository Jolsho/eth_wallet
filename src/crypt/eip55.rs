use alloy::primitives::{Address, Keccak256};

pub fn to_eip55(address: &[u8]) -> String {
    let addr_hex = hex::encode(address);
    let mut hasher = Keccak256::new();
    hasher.update(addr_hex.as_bytes());
    let hash = hasher.finalize();

    let checksummed: String = addr_hex
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_digit(10) {
                c
            } else {
                let hash_nibble = (hash[i / 2] >> (4 * (1 - i % 2))) & 0xF;
                if hash_nibble >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            }
        })
        .collect();

    format!("0x{}", checksummed)
}

pub fn from_eip55(addr_str: &str) -> Result<Address, String> {
    // Strip "0x" prefix if present
    let addr_str = addr_str.strip_prefix("0x").unwrap_or(addr_str);

    // Must be 40 hex characters
    if addr_str.len() != 40 {
        return Err("Invalid address length".to_string());
    }

    // Checksum validation only if mixed-case
    if addr_str.chars().any(|c| c.is_uppercase()) {
        let lowercase = addr_str.to_lowercase();
        let mut hasher = Keccak256::new();
        hasher.update(lowercase.as_bytes());
        let hash = hasher.finalize();
        

        for (i, c) in addr_str.chars().enumerate() {
            if c.is_ascii_alphabetic() {
                let hash_nibble = (hash[i / 2] >> (4 * (1 - i % 2))) & 0xF;
                if hash_nibble >= 8 && !c.is_uppercase() {
                    return Err("Checksum invalid".to_string());
                } else if hash_nibble < 8 && !c.is_lowercase() {
                    return Err("Checksum invalid".to_string());
                }
            }
        }
    }

    // Decode hex to 20 bytes
    let bytes = hex::decode(addr_str).map_err(|_| "Invalid hex".to_string())?;
    let arr: [u8; 20] = bytes.try_into().map_err(|_| "Invalid length".to_string())?;

    Ok(Address::from_slice(&arr))
}

