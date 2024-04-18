extern crate dotenv;

use core::panic;
use std::{
    fs::{self, File},
    io::Read,
};

use ldap3::LdapConnAsync;
use p521::{pkcs8::DecodePublicKey, PublicKey, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[tokio::main]
async fn main() -> Result<(), &'static str> {
    dotenv::dotenv().ok();

    let mut rng = ChaCha20Rng::from_entropy();

    let key_encrypt = SecretKey::random(&mut rng);
    let key_encrypt_public = key_encrypt.public_key();

    let authorized_keys_path = match dotenv::var("AUTHORIZED_KEYS") {
        Ok(val) => val,
        Err(_) => "./keys".to_string(),
    };
    let authroized_keys_files = fs::read_dir(authorized_keys_path.as_str())
        .expect("Failed to read authorized_keys directory");
    let mut authorized_keys = Vec::<PublicKey>::new();
    for file in authroized_keys_files {
        let mut key_file = String::new();

        let path = file.unwrap().path();
        File::open(&path)
            .expect(format!("Failed to open file {:?}", path).as_str())
            .read_to_string(&mut key_file)
            .expect(format!("Failed to read file {:?}", path).as_str());
        let key = PublicKey::from_public_key_pem(key_file.as_str())
            .expect("Failed to load authorized key");
        authorized_keys.push(key);
    }

    if authorized_keys.is_empty() {
        log::error!("No authorized keys found");
        return Err("No authorized keys found");
    }

    let key_sign_path = dotenv::var("KEY_SIGN_PATH").expect("KEY_SIGN_PATH is not provided");
    let mut key_sign_file = String::new();
    File::open(key_sign_path.as_str())
        .expect("Failed to open KEY_SIGN_PATH")
        .read_to_string(&mut key_sign_file)
        .expect("Failed to read from KEY_SIGN_PATH");

    let key_sign = PublicKey::from_public_key_pem(key_sign_file.as_str())
        .expect(format!("Failed to load signing key from {}", key_sign_path).as_str());

    let ldap_host = match dotenv::var("LDAP_HOST") {
        Ok(val) => val,
        Err(_) => {
            log::error!("LDAP_URL is not provided");
            return Err("LDAP_URL is not provided");
        }
    };

    let ldap_user = match dotenv::var("LDAP_USER") {
        Ok(val) => val,
        Err(_) => {
            log::error!("LDAP_USER is not provided");
            return Err("LDAP_USER is not provided");
        }
    };

    let ldap_pass = match dotenv::var("LDAP_PASS") {
        Ok(val) => val,
        Err(_) => {
            log::error!("LDAP_PASS is not provided");
            return Err("LDAP_PASS is not provided");
        }
    };

    let ldap_url = format!("ldap://{}", ldap_host);

    let (conn, mut ldap) = match LdapConnAsync::new(ldap_url.as_str()).await {
        Ok(val) => val,
        Err(e) => {
            log::error!("Failed to connect to LDAP server: {:?}", e);
            return Err("Failed to connect to LDAP server");
        }
    };
    ldap3::drive!(conn);
    println!("Connected to LDAP server");

    let res = match ldap.simple_bind(&ldap_user, &ldap_pass).await {
        Ok(val) => val,
        Err(e) => {
            log::error!("Failed to bind to LDAP server: {:?}", e);
            return Err("Failed to bind to LDAP server");
        }
    };

    if res.clone().success().is_err() {
        panic!("Bind failed: {:?}", res);
    }
    println!("Successfully bound as {}", ldap_user);

    match ldap.unbind().await {
        Ok(_) => println!("Successfully unbound"),
        Err(e) => {
            log::error!("Failed to unbind: {:?}", e);
            return Err("Failed to unbind");
        }
    };

    Ok(())
}
