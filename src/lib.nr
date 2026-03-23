use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};
use std::hash::pedersen_hash;

// BN254_Fq modulus split into (lo, hi) where lo and hi are 128-bit limbs
global BN254_Fq_MODULUS: (Field, Field) =
    (201385395114098847380338600778089168199, 64323764613183177041862057485226039389);

global TWO_POW_128: Field = 0x100000000000000000000000000000000;

pub fn verify_signature<let N: u32>(
    public_key: EmbeddedCurvePoint,
    signature: (EmbeddedCurveScalar, EmbeddedCurveScalar),
    message: [Field; N],
) -> bool {
    let (sig_s, sig_e) = signature;
    // pub_key is on Grumpkin curve
    let mut is_ok = (public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17)
        & (!public_key.is_infinite);

    if ((sig_s.lo != 0) | (sig_s.hi != 0)) & ((sig_e.lo != 0) | (sig_e.hi != 0)) {
        let (r_is_infinite, result) =
            calculate_signature_challenge(public_key, sig_s, sig_e, message);

        is_ok &= !r_is_infinite & (EmbeddedCurveScalar::from_field(result) == sig_e);
    } else {
        is_ok = false;
    }
    is_ok
}

pub fn assert_valid_signature<let N: u32>(
    public_key: EmbeddedCurvePoint,
    signature: (EmbeddedCurveScalar, EmbeddedCurveScalar),
    message: [Field; N],
) {
    let (sig_s, sig_e) = signature;

    // assert pub_key is on Grumpkin curve
    assert(public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17);
    assert(public_key.is_infinite == false);
    // assert signature is not null
    assert((sig_s.lo != 0) | (sig_s.hi != 0));
    assert((sig_e.lo != 0) | (sig_e.hi != 0));

    let (r_is_infinite, result) = calculate_signature_challenge(public_key, sig_s, sig_e, message);

    assert(!r_is_infinite);
    assert_eq(EmbeddedCurveScalar::from_field(result), sig_e);
}

fn calculate_signature_challenge<let N: u32>(
    public_key: EmbeddedCurvePoint,
    sig_s: EmbeddedCurveScalar,
    sig_e: EmbeddedCurveScalar,
    message: [Field; N],
) -> (bool, Field) {
    let g1 = EmbeddedCurvePoint {
        x: 1,
        y: 17631683881184975370165255887551781615748388533673675138860,
        is_infinite: false,
    };
    assert_normalized_signature(sig_s);
    assert_normalized_signature(sig_e);
    let r = multi_scalar_mul([g1, public_key], [sig_s, sig_e]);
    let pedersen_hash = pedersen_hash([r.x, public_key.x, public_key.y]);

    let mut hash_input = [0; N + 1];
    hash_input[0] = pedersen_hash;
    for i in 0..N {
        hash_input[i + 1] = message[i];
    }

    let result = poseidon::poseidon2::Poseidon2::hash(hash_input, N + 1);
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

mod test {
    use super::verify_signature;
    use std::embedded_curve_ops::EmbeddedCurvePoint;
    use std::embedded_curve_ops::EmbeddedCurveScalar;

    #[test]
    fn test_zero_signature() {
        let public_key: EmbeddedCurvePoint = EmbeddedCurvePoint {
            x: 1,
            y: 17631683881184975370165255887551781615748388533673675138860,
            is_infinite: false,
        };
        let signature: (EmbeddedCurveScalar, EmbeddedCurveScalar) =
            (EmbeddedCurveScalar::new(0, 0), EmbeddedCurveScalar::new(0, 0));
        let message: [Field; _] = [2; 64]; // every message
        let verified = verify_signature(public_key, signature, message);
        assert(!verified);
    }

    #[test]
    fn smoke_test() {
        let message: [Field; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let pub_key_x: Field = 0x04b260954662e97f00cab9adb773a259097f7a274b83b113532bce27fa3fb96a;
        let pub_key_y: Field = 0x2fd51571db6c08666b0edfbfbc57d432068bccd0110a39b166ab243da0037197;
        let signature: (EmbeddedCurveScalar, EmbeddedCurveScalar) =
            (EmbeddedCurveScalar::new(1, 0), EmbeddedCurveScalar::new(2, 0));

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
    use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

    #[export]
    pub fn bench_verify_signature(
        public_key: EmbeddedCurvePoint,
        signature: (EmbeddedCurveScalar, EmbeddedCurveScalar),
        message: [Field; 1],
    ) -> bool {
        verify_signature(public_key, signature, message)
    }

    #[export]
    pub fn bench_assert_valid_signature(
        public_key: EmbeddedCurvePoint,
        signature: (EmbeddedCurveScalar, EmbeddedCurveScalar),
        message: [Field; 1],
    ) {
        assert_valid_signature(public_key, signature, message)
    }
}
