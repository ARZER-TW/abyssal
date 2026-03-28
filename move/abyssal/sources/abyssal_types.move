/// Abyssal shared type conversion utilities.
///
/// Provides byte-level helpers for BN254 field element manipulation,
/// ensuring consistency between Circom circuit outputs (LE 32-byte)
/// and Move's native u256/u64 types.
module abyssal::abyssal_types {

    /// Convert 32 bytes (little-endian) to u256.
    public fun bytes32_to_u256(bytes: vector<u8>): u256 {
        assert!(vector::length(&bytes) == 32, 0);
        let mut result: u256 = 0;
        let mut i: u64 = 0;
        while (i < 32) {
            let byte = (*vector::borrow(&bytes, i) as u256);
            result = result | (byte << ((i * 8) as u8));
            i = i + 1;
        };
        result
    }

    /// Convert u256 to 32 bytes (little-endian).
    public fun u256_to_bytes32(value: u256): vector<u8> {
        let mut result = vector::empty<u8>();
        let mut v = value;
        let mut i: u64 = 0;
        while (i < 32) {
            vector::push_back(&mut result, ((v & 0xff) as u8));
            v = v >> 8;
            i = i + 1;
        };
        result
    }

    /// Extract a sub-range of bytes from a vector.
    public fun extract_bytes(data: &vector<u8>, offset: u64, len: u64): vector<u8> {
        let mut result = vector::empty<u8>();
        let mut i = offset;
        while (i < offset + len) {
            vector::push_back(&mut result, *vector::borrow(data, i));
            i = i + 1;
        };
        result
    }

    /// Convert the first 8 bytes (little-endian) to u64.
    public fun le_bytes_to_u64(bytes: vector<u8>): u64 {
        let mut result: u64 = 0;
        let len = vector::length(&bytes);
        let mut i: u64 = 0;
        while (i < 8 && i < len) {
            let byte = (*vector::borrow(&bytes, i) as u64);
            result = result | (byte << ((i * 8) as u8));
            i = i + 1;
        };
        result
    }

    /// Convert u64 to 32 bytes (little-endian, zero-padded).
    /// Used for encoding u64 public inputs as BN254 field elements.
    public fun u64_to_bytes32(value: u64): vector<u8> {
        u256_to_bytes32((value as u256))
    }

    // ========== Tests ==========

    #[test]
    fun test_bytes32_to_u256_zero() {
        let bytes = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(bytes32_to_u256(bytes) == 0u256, 0);
    }

    #[test]
    fun test_bytes32_to_u256_one() {
        let bytes = vector[
            1u8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(bytes32_to_u256(bytes) == 1u256, 0);
    }

    #[test]
    fun test_bytes32_to_u256_large() {
        // 999 in LE = [0xe7, 0x03, 0, 0, ...]
        let mut bytes = vector[0xe7u8, 0x03];
        let mut i = 0;
        while (i < 30) { vector::push_back(&mut bytes, 0u8); i = i + 1; };
        assert!(bytes32_to_u256(bytes) == 999u256, 0);
    }

    #[test]
    fun test_u256_to_bytes32_roundtrip() {
        let value = 123456789u256;
        let bytes = u256_to_bytes32(value);
        assert!(vector::length(&bytes) == 32, 0);
        assert!(bytes32_to_u256(bytes) == value, 1);
    }

    #[test]
    fun test_extract_bytes() {
        let data = vector[10u8, 20, 30, 40, 50];
        let sub = extract_bytes(&data, 1, 3);
        assert!(vector::length(&sub) == 3, 0);
        assert!(*vector::borrow(&sub, 0) == 20, 1);
        assert!(*vector::borrow(&sub, 1) == 30, 2);
        assert!(*vector::borrow(&sub, 2) == 40, 3);
    }

    #[test]
    fun test_le_bytes_to_u64() {
        // 42 in LE
        let bytes = vector[42u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(le_bytes_to_u64(bytes) == 42, 0);
    }

    #[test]
    fun test_u64_to_bytes32() {
        let bytes = u64_to_bytes32(42);
        assert!(vector::length(&bytes) == 32, 0);
        assert!(*vector::borrow(&bytes, 0) == 42, 1);
        assert!(*vector::borrow(&bytes, 8) == 0, 2);
    }
}
