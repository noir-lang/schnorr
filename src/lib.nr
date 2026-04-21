use poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

global TWO_POW_128: Field = 0x100000000000000000000000000000000;

pub fn verify_signature(
    public_key: EmbeddedCurvePoint,
    signature: [u8; 64],
    message: Field,
) -> bool {
    let sig_s = scalar_from_bytes(signature, 0);
    let sig_e = scalar_from_bytes(signature, 32);
    let mut is_ok = is_on_curve(public_key) & (!public_key.is_infinite);

    if ((sig_s.lo != 0) | (sig_s.hi != 0)) & ((sig_e.lo != 0) | (sig_e.hi != 0)) {
        let (r_is_infinite, e_computed) =
            calculate_signature_challenge(public_key, sig_s, sig_e, message);

        is_ok &= !r_is_infinite;
        let sig_e_field = sig_e.lo + sig_e.hi * TWO_POW_128;
        is_ok &= e_computed == sig_e_field;
    } else {
        is_ok = false;
    }
    is_ok
}

pub fn assert_valid_signature(public_key: EmbeddedCurvePoint, signature: [u8; 64], message: Field) {
    let sig_s = scalar_from_bytes(signature, 0);
    let sig_e = scalar_from_bytes(signature, 32);

    assert(is_on_curve(public_key));
    assert(public_key.is_infinite == false);
    assert((sig_s.lo != 0) | (sig_s.hi != 0));
    assert((sig_e.lo != 0) | (sig_e.hi != 0));

    let (r_is_infinite, e_computed) =
        calculate_signature_challenge(public_key, sig_s, sig_e, message);

    assert(!r_is_infinite);
    let sig_e_field = sig_e.lo + sig_e.hi * TWO_POW_128;
    assert(e_computed == sig_e_field);
}

/// e = Poseidon2(R.x, pubkey.x, pubkey.y, message)
///
/// Mirrors the native C++ implementation: the Poseidon2 sponge operates over the BN254 scalar
/// field (= grumpkin base field = Noir's Field). Since Field modulus < grumpkin scalar modulus,
/// the challenge embeds losslessly into the grumpkin scalar field for the signature equation.
fn calculate_signature_challenge(
    public_key: EmbeddedCurvePoint,
    sig_s: EmbeddedCurveScalar,
    sig_e: EmbeddedCurveScalar,
    message: Field,
) -> (bool, Field) {
    let g1 = EmbeddedCurvePoint {
        x: 1,
        y: 17631683881184975370165255887551781615748388533673675138860,
        is_infinite: false,
    };
    let r = multi_scalar_mul([g1, public_key], [sig_s, sig_e]);
    let e = Poseidon2::hash([r.x, public_key.x, public_key.y, message], 4);
    (r.is_infinite, e)
}

fn is_on_curve(point: EmbeddedCurvePoint) -> bool {
    point.y * point.y == point.x * point.x * point.x - 17
}

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
        let message: Field = 0x1234;
        let verified = verify_signature(public_key, signature, message);
        assert(!verified);
    }
}

mod bench {
    use super::{assert_valid_signature, verify_signature};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    #[export]
    pub fn bench_verify_signature(
        public_key: EmbeddedCurvePoint,
        signature: [u8; 64],
        message: Field,
    ) -> bool {
        verify_signature(public_key, signature, message)
    }

    #[export]
    pub fn bench_assert_valid_signature(
        public_key: EmbeddedCurvePoint,
        signature: [u8; 64],
        message: Field,
    ) {
        assert_valid_signature(public_key, signature, message)
    }
}
