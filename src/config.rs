use std::{
    fmt::Debug,
    fs::{self, File},
    io::{self, Read},
};

use elliptic_curve::{pkcs8::DecodePublicKey, PublicKey};
use pkcs8::AssociatedOid;

use bign256::BignP256;
use p192::NistP192;
use p224::NistP224;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use sm2::Sm2;

use rasn::{
    types::{BitString, ObjectIdentifier, SequenceOf},
    AsnType, Decode,
};
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};

use crate::types::{ECPublicKey, PublicKeyWrap};

#[derive(AsnType, Decode)]
struct PublicKeyAsn {
    metadata: SequenceOf<ObjectIdentifier>,
    _data: BitString,
}

pub enum LoadError {
    RSALoadError(pkcs1::Error),
    ECLoadError(spki::Error),
}

pub enum LoadKeysError {
    CanonicalizeError(String, io::Error),
    ListDirError(String, io::Error),
}

pub enum LoadKeyError {
    DecodeError(pem_rfc7468::Error),
    FileTypeError(String),
    FileLoadError(LoadError),
    FileDecodeError(rasn::error::DecodeError),
    FileOidError(const_oid::Error),
    UnsupportedCurve(const_oid::ObjectIdentifier),
}

impl Debug for LoadKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadKeyError::DecodeError(err) => {
                write!(f, "Error occured while parsing key: {:?}", err)
            }
            LoadKeyError::FileTypeError(label) => write!(f, "Unknown key type label: {}", label),
            LoadKeyError::FileLoadError(err) => match err {
                LoadError::RSALoadError(err) => write!(f, "Failed to load RSA key: {:?}", err),
                LoadError::ECLoadError(err) => write!(f, "Failed to load EC key: {:?}", err),
            },
            LoadKeyError::FileDecodeError(err) => {
                write!(f, "Error occured while decoding file: {:?}", err)
            }
            LoadKeyError::FileOidError(err) => {
                write!(f, "Error occured while loading OID: {:?}", err)
            }
            LoadKeyError::UnsupportedCurve(err) => {
                write!(f, "Unsupported Curve with OID {} found", err)
            }
        }
    }
}

pub fn load_public_keys(path: String) -> Result<Vec<PublicKeyWrap>, LoadKeysError> {
    let path_canonical = match fs::canonicalize(&path) {
        Ok(val) => val.to_str().unwrap().to_string(),
        Err(err) => {
            trace!("Authorized keys path: {}", path.as_str());
            return Err(LoadKeysError::CanonicalizeError(path, err));
        }
    };

    let files = match fs::read_dir(path_canonical.as_str()) {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadKeysError::ListDirError(path, err));
        }
    };

    // let mut authorized_keys: Vec = Vec::new();
    let mut keys = Vec::<PublicKeyWrap>::new();
    for file in files {
        let filepath = file.unwrap().path();

        if filepath.is_dir() {
            warn!(
                "Authorized Key Directory({}) contains a folder \"{}\", but recursive reading is not supported",
                path_canonical,
                filepath.file_name().unwrap().to_str().unwrap()
            );
            continue;
        }

        let mut file = match File::open(&filepath) {
            Ok(val) => val,
            Err(_) => {
                error!("Failed to open file {}", filepath.display());
                continue;
            }
        };

        let mut content = String::new();
        if let Err(_) = file.read_to_string(&mut content) {
            error!("Failed to read file {}", filepath.display());
            continue;
        }

        match load_public_key(content) {
            Ok(val) => keys.push(val),
            Err(err) => {
                error!("Failed to load public key from file {}", filepath.display(),);
                error!("{:?}", err);
                continue;
            }
        }
    }

    Ok(keys)
}

pub fn load_public_key(key: String) -> Result<PublicKeyWrap, LoadKeyError> {
    let (label, data) = match pem_rfc7468::decode_vec(&mut key.as_bytes()) {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadKeyError::DecodeError(err));
        }
    };

    if !label.ends_with("PUBLIC KEY") {
        return Err(LoadKeyError::FileTypeError(label.to_string()));
    }

    if label == "RSA PUBLIC KEY" {
        match RsaPublicKey::from_pkcs1_pem(&key) {
            Ok(val) => return Ok(PublicKeyWrap::RSA(val)),
            Err(err) => return Err(LoadKeyError::FileLoadError(LoadError::RSALoadError(err))),
        };
    } else if label == "PUBLIC KEY" {
        let curve = match rasn::der::decode::<PublicKeyAsn>(&data) {
            Ok(val) => val,
            Err(err) => {
                return Err(LoadKeyError::FileDecodeError(err));
            }
        };

        let oid = match pkcs8::ObjectIdentifier::from_arcs(curve.metadata[1].iter().copied()) {
            Ok(val) => val,
            Err(err) => {
                return Err(LoadKeyError::FileOidError(err));
            }
        };

        return Ok(match oid {
            BignP256::OID => match PublicKey::<BignP256>::from_public_key_der(&data) {
                Ok(val) => PublicKeyWrap::EC(ECPublicKey::BignP256(val)),
                Err(err) => return Err(LoadKeyError::FileLoadError(LoadError::ECLoadError(err))),
            },
            NistP192::OID => match PublicKey::<NistP192>::from_public_key_der(&data) {
                Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP192(val)),
                Err(err) => return Err(LoadKeyError::FileLoadError(LoadError::ECLoadError(err))),
            },
            NistP224::OID => match PublicKey::<NistP224>::from_public_key_der(&data) {
                Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP224(val)),
                Err(err) => return Err(LoadKeyError::FileLoadError(LoadError::ECLoadError(err))),
            },
            NistP256::OID => match PublicKey::<NistP256>::from_public_key_der(&data) {
                Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP256(val)),
                Err(err) => return Err(LoadKeyError::FileLoadError(LoadError::ECLoadError(err))),
            },
            NistP384::OID => match PublicKey::<NistP384>::from_public_key_der(&data) {
                Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP384(val)),
                Err(err) => return Err(LoadKeyError::FileLoadError(LoadError::ECLoadError(err))),
            },
            NistP521::OID => match PublicKey::<NistP521>::from_public_key_der(&data) {
                Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP521(val)),
                Err(err) => return Err(LoadKeyError::FileLoadError(LoadError::ECLoadError(err))),
            },
            Sm2::OID => match PublicKey::<Sm2>::from_public_key_der(&data) {
                Ok(val) => PublicKeyWrap::EC(ECPublicKey::Sm2(val)),
                Err(err) => return Err(LoadKeyError::FileLoadError(LoadError::ECLoadError(err))),
            },
            _ => return Err(LoadKeyError::UnsupportedCurve(oid)),
        });
    }

    return Err(LoadKeyError::FileTypeError(label.to_string()));
}
