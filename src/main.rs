extern crate dotenv;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use core::panic;
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

use elliptic_curve::{pkcs8::DecodePublicKey, PublicKey};
use ldap3::LdapConnAsync;
use p521::SecretKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn read_public_key_pem_file(path: impl AsRef<Path>) -> Result<PublicKey, ()> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let key = PublicKey::decode_pem(contents.as_bytes())?;
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<(), i8> {
    dotenv::dotenv().ok();

    pretty_env_logger::init();

    let mut rng = ChaCha20Rng::from_entropy();

    let key_encrypt = SecretKey::random(&mut rng);
    let key_encrypt_public = key_encrypt.public_key();

    let authorized_keys_path = match dotenv::var("AUTHORIZED_KEYS") {
        Ok(val) => val,
        Err(_) => "./keys".to_string(),
    };

    let authorized_keys_files = match fs::read_dir(authorized_keys_path.as_str()) {
        Ok(val) => val,
        Err(_) => {
            error!("Failed to read authorized keys directory");
            return Err(-1);
        }
    };
    let mut authorized_keys = Vec::<PublicKey>::new();
    for file in authorized_keys_files {
        let path = file.unwrap().path();
        let key = match PublicKey::read_public_key_pem_file(&path) {
            Ok(val) => val,
            Err(err) => {
                error!("Failed to load key \"{}\"", path.to_str().unwrap());
                error!("{}", err);
                return Err(-2);
            }
        };
        authorized_keys.push(key);
    }

    if authorized_keys.is_empty() {
        error!("No authorized keys found");
        return Err(-3);
    }

    Ok(())
}
