pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub fn fold64(mut seed: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        seed ^= b as u64;
        seed = seed.wrapping_mul(0x1000_0000_01b3);
        seed ^= seed.rotate_left(17);
    }
    seed
}

pub fn station_digest(site_id: u32, port_id: u16, payload: &[u8]) -> u64 {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    seed ^= site_id as u64;
    seed = seed.rotate_left(11) ^ ((port_id as u64) << 32);
    fold64(seed, payload)
}

pub fn rolling_window_score(bytes: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in bytes {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}
