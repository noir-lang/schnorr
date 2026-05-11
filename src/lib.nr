use poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

global TWO_POW_128: Field = 0x100000000000000000000000000000000;

pub fn verify_signature(
    public_key: EmbeddedCurvePoint,
    signature: (EmbeddedCurveScalar, EmbeddedCurveScalar),
    message: Field,
) -> bool {
    let (sig_s, sig_e) = signature;
    let mut is_ok = is_on_curve(public_key);

    let zero = EmbeddedCurveScalar::new(0, 0);
    if ((sig_s != zero) & (sig_e != zero)) {
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

pub fn assert_valid_signature(
    public_key: EmbeddedCurvePoint,
    signature: (EmbeddedCurveScalar, EmbeddedCurveScalar),
    message: Field,
) {
    let (sig_s, sig_e) = signature;

    assert(is_on_curve(public_key));
    let zero = EmbeddedCurveScalar::new(0, 0);
    assert(sig_s != zero);
    assert(sig_e != zero);

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
    let g1 = EmbeddedCurvePoint::generator();
    let r = multi_scalar_mul([g1, public_key], [sig_s, sig_e]);
    let e = Poseidon2::hash([r.x, public_key.x, public_key.y, message], 4);
    (r.is_infinite(), e)
}

fn is_on_curve(point: EmbeddedCurvePoint) -> bool {
    point.y * point.y == point.x * point.x * point.x - 17
}

mod test {
    use super::verify_signature;
    use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

    #[test]
    fn zero_signature() {
        let public_key: EmbeddedCurvePoint = EmbeddedCurvePoint::generator();
        let signature: (EmbeddedCurveScalar, EmbeddedCurveScalar) =
            (EmbeddedCurveScalar::new(0, 0), EmbeddedCurveScalar::new(0, 0));
        let message: Field = 0x1234;
        let verified = verify_signature(public_key, signature, message);
        assert(!verified);
    }

    // Pinned test vector mirroring the C++ `schnorr.pinned_test_vector_small` test.
    #[test]
    fn pinned_vector_small() {
        let public_key = EmbeddedCurvePoint::new(
            0x2c39bbbde2d0ffcb5c4317dcbfa1771cf554a2f33c647446632fa707a5bf5f3f,
            0x2b9c81935298af5ebe22f1a7279bb76781e6cadba3fb6c5c41ed942392dc687c,
        );
        let sig_s = EmbeddedCurveScalar::new(
            0x28a5278efa70b5bed7a1a00db7874926,
            0x2e5369edb9c537abb7009429f27005e4,
        );
        let sig_e = EmbeddedCurveScalar::new(
            0xf8885875459c1bfb37a446223a323f52,
            0x0aa3af2d0820967a929db740196db453,
        );
        let message: Field = 0x2bc;
        assert(verify_signature(public_key, (sig_s, sig_e), message));
    }

    // Pinned test vector mirroring the C++ `schnorr.pinned_test_vector_large` test.
    #[test]
    fn pinned_vector_large() {
        let public_key = EmbeddedCurvePoint::new(
            0x065812e335a97c2108ea8cf4ccfe2f9dd6b117a0714f5e18461575be93f61da6,
            0x1a915003e8ec534f9a15d926a7ded478e178468ccc4f28e236e67450a55ac622,
        );
        let sig_s = EmbeddedCurveScalar::new(
            0xdaf71612d4c3e50e9166fce768e6fa9a,
            0x079b7d2ee637567708798f1fc5d1d9b9,
        );
        let sig_e = EmbeddedCurveScalar::new(
            0x4aba6c0ac04353fb9fd87a6b03067106,
            0x02371e738a5ae0234b416beb3903d9ab,
        );
        let message: Field = 0x0123456789abcdef0fedcba9876543210123456789abcdef0fedcba987654321;
        assert(verify_signature(public_key, (sig_s, sig_e), message));
    }
}

mod bench {
    use super::{assert_valid_signature, verify_signature};
    use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

    #[export]
    pub fn bench_verify_signature(
        public_key: EmbeddedCurvePoint,
        signature: (EmbeddedCurveScalar, EmbeddedCurveScalar),
        message: Field,
    ) -> bool {
        verify_signature(public_key, signature, message)
    }

    #[export]
    pub fn bench_assert_valid_signature(
        public_key: EmbeddedCurvePoint,
        signature: (EmbeddedCurveScalar, EmbeddedCurveScalar),
        message: Field,
    ) {
        assert_valid_signature(public_key, signature, message)
    }
}
