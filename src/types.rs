use rsa::{pss::Pss, RsaPublicKey};

use ecdsa::{signature::Verifier, Signature, VerifyingKey};
use elliptic_curve::PublicKey;

use bign256::BignP256;
use p192::NistP192;
use p224::NistP224;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use sm2::Sm2;

pub enum ECPublicKey {
    BignP256(PublicKey<BignP256>),
    NistP192(PublicKey<NistP192>),
    NistP224(PublicKey<NistP224>),
    NistP256(PublicKey<NistP256>),
    NistP384(PublicKey<NistP384>),
    NistP521(PublicKey<NistP521>),
    Sm2(PublicKey<Sm2>),
}

pub enum PublicKeyWrap {
    RSA(RsaPublicKey),
    EC(ECPublicKey),
}

trait Verify {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, i8>;
}

impl PartialEq for PublicKeyWrap {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PublicKeyWrap::RSA(a), PublicKeyWrap::RSA(b)) => a == b,
            (PublicKeyWrap::EC(a), PublicKeyWrap::EC(b)) => match (a, b) {
                (ECPublicKey::BignP256(a), ECPublicKey::BignP256(b)) => a == b,
                (ECPublicKey::NistP192(a), ECPublicKey::NistP192(b)) => a == b,
                (ECPublicKey::NistP224(a), ECPublicKey::NistP224(b)) => a == b,
                (ECPublicKey::NistP256(a), ECPublicKey::NistP256(b)) => a == b,
                (ECPublicKey::NistP384(a), ECPublicKey::NistP384(b)) => a == b,
                (ECPublicKey::NistP521(a), ECPublicKey::NistP521(b)) => a == b,
                (ECPublicKey::Sm2(a), ECPublicKey::Sm2(b)) => a == b,
                _ => false,
            },
            _ => false,
        }
    }
}

impl Verify for PublicKeyWrap {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, i8> {
        match self {
            PublicKeyWrap::RSA(key) => {
                let scheme = Pss::new();
                match key.verify(scheme, data, signature) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            PublicKeyWrap::EC(key) => match key {
                ECPublicKey::BignP256(key) => {
                    let verifier = VerifyingKey::<BignP256>::from_affine(*key.as_affine());
                    let signature = verifier.
                    Ok(true)
                },
                ECPublicKey::NistP192(key) => {
                    let verifier = VerifyingKey::<NistP192>::from_affine(*key.as_affine());
                    let signature = verifier.verify(data, signature);
                    Ok(true)
                },
                ECPublicKey::NistP224(key) => {
                    let verifier = VerifyingKey::<NistP224>::from_affine(*key.as_affine());
                    let signature = verifier.verify(data, signature);
                    Ok(true)
                },
                ECPublicKey::NistP256(key) => {
                    let verifier = VerifyingKey::<NistP256>::from_affine(*key.as_affine());
                    let signature = verifier.verify(data, signature);
                    Ok(true)
                },
                ECPublicKey::NistP384(key) => {
                    let verifier = VerifyingKey::<NistP384>::from_affine(*key.as_affine());
                    let signature = verifier.verify(data, signature);
                    Ok(true)
                },
                ECPublicKey::NistP521(key) => {
                    let verifier = VerifyingKey::<NistP521>::from_affine(*key.as_affine());
                    let signature = verifier.verify(data, signature);
                    Ok(true)
                },
                ECPublicKey::Sm2(key) => {
                    let verifier = VerifyingKey::<Sm2>::from_affine(*key.as_affine());
                    let signature = verifier.verify(data, signature);
                    Ok(true)
                },,
            },
        }
    }
}
