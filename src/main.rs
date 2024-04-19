extern crate dotenv;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use std::{
    fs::{self, File},
    io::Read,
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

#[derive(AsnType, Decode)]
struct PublicKeyAsn {
    metadata: SequenceOf<ObjectIdentifier>,
    _data: BitString,
}

enum ECPublicKey {
    BignP256(PublicKey<BignP256>),
    NistP192(PublicKey<NistP192>),
    NistP224(PublicKey<NistP224>),
    NistP256(PublicKey<NistP256>),
    NistP384(PublicKey<NistP384>),
    NistP521(PublicKey<NistP521>),
    Sm2(PublicKey<Sm2>),
}

enum PublicKeyWrap {
    RSA(RsaPublicKey),
    EC(ECPublicKey),
}

#[tokio::main]
async fn main() -> Result<(), i8> {
    dotenv::dotenv().ok();

    pretty_env_logger::init();

    // let mut rng = ChaCha20Rng::from_entropy();

    // let key_encrypt = SecretKey::random(&mut rng);
    // let _key_encrypt_public = key_encrypt.public_key();

    let mut authorized_keys_path = match dotenv::var("AUTHORIZED_KEYS") {
        Ok(val) => val,
        Err(_) => "./keys".to_string(),
    };

    authorized_keys_path = match fs::canonicalize(&authorized_keys_path) {
        Ok(val) => val.to_str().unwrap().to_string(),
        Err(_) => {
            trace!("Authorized keys path: {}", authorized_keys_path.as_str());
            error!("Failed to canonicalize authorized keys path");
            return Err(-2);
        }
    };

    let authorized_keys_files = match fs::read_dir(authorized_keys_path.as_str()) {
        Ok(val) => val,
        Err(_) => {
            error!("Failed to read authorized keys directory");
            return Err(-1);
        }
    };

    // let mut authorized_keys: Vec = Vec::new();
    let mut authorized_keys = Vec::<PublicKeyWrap>::new();
    for file in authorized_keys_files {
        let path = file.unwrap().path();

        if path.is_dir() {
            warn!(
                "Authorized Key Directory({}) contains a folder \"{}\", but recursive reading is not supported",
                authorized_keys_path,
                path.file_name().unwrap().to_str().unwrap()
            );
            continue;
        }

        let mut file = match File::open(&path) {
            Ok(val) => val,
            Err(_) => {
                error!("Failed to open file {}", path.display());
                continue;
            }
        };

        let mut contents = String::new();
        if let Err(_) = file.read_to_string(&mut contents) {
            error!("Failed to read file {}", path.display());
            continue;
        }

        let (type_label, data) = match pem_rfc7468::decode_vec(&mut contents.as_bytes()) {
            Ok(val) => val,
            Err(_) => {
                error!("Failed to decode file {}", path.display());
                continue;
            }
        };

        if !type_label.ends_with("PUBLIC KEY") {
            error!("Unknown PEM type label for file {}", path.display());
            error!("Expected \"PUBLIC KEY\", got \"{}\"", type_label);
            continue;
        }

        if type_label == "RSA PUBLIC KEY" {
            let key = match RsaPublicKey::from_pkcs1_pem(&contents) {
                Ok(val) => PublicKeyWrap::RSA(val),
                Err(_) => {
                    error!(
                        "Failed to parse RSA public key from file {}",
                        path.display()
                    );
                    continue;
                }
            };

            authorized_keys.push(key);
        } else if type_label == "PUBLIC KEY" {
            let curve = match rasn::der::decode::<PublicKeyAsn>(&data) {
                Ok(val) => val,
                Err(_) => {
                    error!("Failed to parse EC public key from file {}", path.display());
                    continue;
                }
            };

            let oid = match pkcs8::ObjectIdentifier::from_arcs(curve.metadata[1].iter().copied()) {
                Ok(val) => val,
                Err(_) => {
                    error!("Failed to parse EC public key from file {}", path.display());
                    error!(
                        "Unknown EC curve OID {}",
                        curve.metadata[1]
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<String>>()
                            .join(".")
                    );
                    continue;
                }
            };

            trace!("Found EC curve OID {}", oid.to_string());

            let key = match oid {
                BignP256::OID => match PublicKey::<BignP256>::from_public_key_der(&data) {
                    Ok(val) => PublicKeyWrap::EC(ECPublicKey::BignP256(val)),
                    Err(_) => {
                        error!("Failed to parse EC public key from file {}", path.display());
                        continue;
                    }
                },
                NistP192::OID => match PublicKey::<NistP192>::from_public_key_der(&data) {
                    Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP192(val)),
                    Err(_) => {
                        error!("Failed to parse EC public key from file {}", path.display());
                        continue;
                    }
                },
                NistP224::OID => match PublicKey::<NistP224>::from_public_key_der(&data) {
                    Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP224(val)),
                    Err(_) => {
                        error!("Failed to parse EC public key from file {}", path.display());
                        continue;
                    }
                },
                NistP256::OID => match PublicKey::<NistP256>::from_public_key_der(&data) {
                    Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP256(val)),
                    Err(_) => {
                        error!("Failed to parse EC public key from file {}", path.display());
                        continue;
                    }
                },
                NistP384::OID => match PublicKey::<NistP384>::from_public_key_der(&data) {
                    Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP384(val)),
                    Err(_) => {
                        error!("Failed to parse EC public key from file {}", path.display());
                        continue;
                    }
                },
                NistP521::OID => match PublicKey::<NistP521>::from_public_key_der(&data) {
                    Ok(val) => PublicKeyWrap::EC(ECPublicKey::NistP521(val)),
                    Err(_) => {
                        error!("Failed to parse EC public key from file {}", path.display());
                        continue;
                    }
                },
                Sm2::OID => match PublicKey::<Sm2>::from_public_key_der(&data) {
                    Ok(val) => PublicKeyWrap::EC(ECPublicKey::Sm2(val)),
                    Err(_) => {
                        error!("Failed to parse EC public key from file {}", path.display());
                        continue;
                    }
                },
                _ => {
                    error!(
                        "Unsupported EC curve for file {} with OID {}",
                        path.display(),
                        curve.metadata[1]
                            .to_vec()
                            .iter()
                            .map(|x| format!("{}", x))
                            .collect::<Vec<String>>()
                            .join(".")
                    );
                    continue;
                }
            };

            authorized_keys.push(key);
        } else {
            error!("Unknown PEM type label for file {}", path.display());
            error!(
                "Expected \"RSA PUBLIC KEY\" or \"PUBLIC KEY\", got \"{}\"",
                type_label
            );
            continue;
        }
    }

    info!("Found {} authorized keys", authorized_keys.len());

    if authorized_keys.is_empty() {
        error!("No authorized keys found");
        return Err(-3);
    }

    Ok(())
}
