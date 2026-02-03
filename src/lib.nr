use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};
use std::hash::{blake2s, pedersen_hash};

// BN254_Fq modulus split into (lo, hi) where lo and hi are 128-bit limbs
global BN254_Fq_MODULUS: (Field, Field) =
    (201385395114098847380338600778089168199, 64323764613183177041862057485226039389);

global TWO_POW_128: Field = 0x100000000000000000000000000000000;

pub fn verify_signature<let N: u32>(
    public_key: EmbeddedCurvePoint,
    signature: [u8; 64],
    message: [u8; N],
) -> bool {
    //scalar lo/hi from bytes
    let sig_s = scalar_from_bytes(signature, 0);
    let sig_e = scalar_from_bytes(signature, 32);
    // pub_key is on Grumpkin curve
    let mut is_ok = (public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17)
        & (!public_key.is_infinite);

    if ((sig_s.lo != 0) | (sig_s.hi != 0)) & ((sig_e.lo != 0) | (sig_e.hi != 0)) {
        let (r_is_infinite, result) =
            calculate_signature_challenge(public_key, sig_s, sig_e, message);

        is_ok &= !r_is_infinite;
        for i in 0..32 {
            is_ok &= result[i] == signature[32 + i];
        }
    } else {
        is_ok = false;
    }
    is_ok
}

pub fn assert_valid_signature<let N: u32>(
    public_key: EmbeddedCurvePoint,
    signature: [u8; 64],
    message: [u8; N],
) {
    //scalar lo/hi from bytes
    let sig_s = scalar_from_bytes(signature, 0);
    let sig_e = scalar_from_bytes(signature, 32);

    // assert pub_key is on Grumpkin curve
    assert(public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17);
    assert(public_key.is_infinite == false);
    // assert signature is not null
    assert((sig_s.lo != 0) | (sig_s.hi != 0));
    assert((sig_e.lo != 0) | (sig_e.hi != 0));

    let (r_is_infinite, result) = calculate_signature_challenge(public_key, sig_s, sig_e, message);

    assert(!r_is_infinite);
    for i in 0..32 {
        assert(result[i] == signature[32 + i]);
    }
}

fn calculate_signature_challenge<let N: u32>(
    public_key: EmbeddedCurvePoint,
    sig_s: EmbeddedCurveScalar,
    sig_e: EmbeddedCurveScalar,
    message: [u8; N],
) -> (bool, [u8; 32]) {
    let g1 = EmbeddedCurvePoint {
        x: 1,
        y: 17631683881184975370165255887551781615748388533673675138860,
        is_infinite: false,
    };
    assert_normalized_signature(sig_s);
    assert_normalized_signature(sig_e);
    let r = multi_scalar_mul([g1, public_key], [sig_s, sig_e]);
    // compare the _hashes_ rather than field elements modulo r
    let pedersen_hash = pedersen_hash([r.x, public_key.x, public_key.y]);
    let pde: [u8; 32] = pedersen_hash.to_be_bytes();

    let mut hash_input = [0; N + 32];
    for i in 0..32 {
        hash_input[i] = pde[i];
    }
    for i in 0..N {
        hash_input[32 + i] = message[i];
    }

    let result = blake2s(hash_input);
    (r.is_infinite, result)
}

unconstrained fn __gt(a: Field, b: Field) -> bool {
    b.lt(a)
}

// this method asserts the signature is in the range [0, BN254_Fq_MODULUS)
fn assert_normalized_signature(sig_e: EmbeddedCurveScalar) {
    let hi = sig_e.hi;
    let lo = sig_e.lo;
    let MODULUS = BN254_Fq_MODULUS;

    // validate that lo and hi are positive (fit in 128 bits)
    lo.assert_max_bit_size::<128>();
    hi.assert_max_bit_size::<128>();

    // validate that (hi, lo) < MODULUS by checking (MODULUS - 1) - (hi, lo) >= 0
    let modulus_minus_1_lo = MODULUS.0 - 1;
    let modulus_minus_1_hi = MODULUS.1;

    // Safety: __gt is a simple comparison used to hint the borrow value, which is then constrained
    let borrow = unsafe { __gt(lo, modulus_minus_1_lo) };
    let rplo = modulus_minus_1_lo - lo + borrow as Field * TWO_POW_128;
    let rphi = modulus_minus_1_hi - hi - borrow as Field;

    // constrain that rplo and rphi are non-negative
    rplo.assert_max_bit_size::<128>();
    rphi.assert_max_bit_size::<128>();
}

//Bytes to scalar: take the first (after the specified offset) 16 bytes of the input as the lo value, and the next 16 bytes as the hi value
fn scalar_from_bytes(bytes: [u8; 64], offset: u32) -> EmbeddedCurveScalar {
    let mut v: Field = 1;
    let mut lo: Field = 0;
    let mut hi: Field = 0;
    for i in 0..16 {
        lo = lo + (bytes[offset + 31 - i] as Field) * v;
        hi = hi + (bytes[offset + 15 - i] as Field) * v;
        v = v * 256;
    }
    let sig_s = EmbeddedCurveScalar::new(lo, hi);
    sig_s
}

mod test {
    use super::verify_signature;
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    #[test]
    fn test_zero_signature() {
        let public_key: EmbeddedCurvePoint = EmbeddedCurvePoint {
            x: 1,
            y: 17631683881184975370165255887551781615748388533673675138860,
            is_infinite: false,
        };
        let signature: [u8; 64] = [0; 64];
        let message: [u8; _] = [2; 64]; // every message
        let verified = verify_signature(public_key, signature, message);
        assert(!verified);
    }

    #[test]
    fn smoke_test() {
        let message: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let pub_key_x: Field = 0x04b260954662e97f00cab9adb773a259097f7a274b83b113532bce27fa3fb96a;
        let pub_key_y: Field = 0x2fd51571db6c08666b0edfbfbc57d432068bccd0110a39b166ab243da0037197;
        let signature: [u8; 64] = [
            1, 13, 119, 112, 212, 39, 233, 41, 84, 235, 255, 93, 245, 172, 186, 83, 157, 253, 76,
            77, 33, 128, 178, 15, 214, 67, 105, 107, 177, 234, 77, 48, 27, 237, 155, 84, 39, 84,
            247, 27, 22, 8, 176, 230, 24, 115, 145, 220, 254, 122, 135, 179, 171, 4, 214, 202, 64,
            199, 19, 84, 239, 138, 124, 12,
        ];

        let pub_key = EmbeddedCurvePoint { x: pub_key_x, y: pub_key_y, is_infinite: false };
        let valid_signature = verify_signature(pub_key, signature, message);
        assert(valid_signature);
        super::assert_valid_signature(pub_key, signature, message);
    }

    mod assert_normalized_signature {
        use crate::{assert_normalized_signature, BN254_Fq_MODULUS};
        use std::embedded_curve_ops::EmbeddedCurveScalar;

        #[test]
        fn should_pass_for_small_value() {
            let sig_e = EmbeddedCurveScalar::new(23325341, 0);
            assert_normalized_signature(sig_e);
        }

        #[test]
        fn should_pass_for_max_valid_value() {
            let sig_e = EmbeddedCurveScalar::new(BN254_Fq_MODULUS.0 - 1, BN254_Fq_MODULUS.1);
            assert_normalized_signature(sig_e);
        }

        #[test(should_fail)]
        fn should_fail_when_equal_to_modulus() {
            let sig_e = EmbeddedCurveScalar::new(BN254_Fq_MODULUS.0, BN254_Fq_MODULUS.1);
            assert_normalized_signature(sig_e);
        }

        #[test(should_fail)]
        fn should_fail_when_greater_than_modulus() {
            let sig_e = EmbeddedCurveScalar::new(BN254_Fq_MODULUS.0 + 1, BN254_Fq_MODULUS.1);
            assert_normalized_signature(sig_e);
        }
    }
}

mod bench {
    use super::{assert_valid_signature, verify_signature};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    #[export]
    pub fn bench_verify_signature(
        public_key: EmbeddedCurvePoint,
        signature: [u8; 64],
        message: [u8; 32],
    ) -> bool {
        verify_signature(public_key, signature, message)
    }

    #[export]
    pub fn bench_assert_valid_signature(
        public_key: EmbeddedCurvePoint,
        signature: [u8; 64],
        message: [u8; 32],
    ) {
        assert_valid_signature(public_key, signature, message)
    }
}
