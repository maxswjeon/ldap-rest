mod config;
mod routes;
mod types;

use std::sync::Arc;

extern crate dotenv;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use axum::{
    routing::{get, post},
    Router,
};

use elliptic_curve::rand_core::SeedableRng;
use p521::SecretKey;
use pkcs8::{EncodePublicKey, LineEnding};
use rand_chacha::ChaCha20Rng;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), i8> {
    tracing_subscriber::fmt::init();

    dotenv::dotenv().ok();

    let mut rng = ChaCha20Rng::from_entropy();
    let key_encrypt = SecretKey::random(&mut rng);
    let key_encrypt_public = match key_encrypt.public_key().to_public_key_pem(LineEnding::LF) {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to encode public key: {}", err);
            return Err(-1);
        }
    };

    let authorized_keys_path =
        dotenv::var("AUTHORIZED_KEYS").unwrap_or_else(|_| "./keys".to_string());

    let authorized_keys = match config::load_public_keys(authorized_keys_path) {
        Ok(val) => val,
        Err(err) => match err {
            config::LoadKeysError::CanonicalizeError(_path, err) => {
                error!("Failed to canonicalize authorized keys path:{}", err);
                return Err(-2);
            }
            config::LoadKeysError::ListDirError(_path, err) => {
                error!("Failed to list contents of authorized keys folder: {}", err);
                return Err(-3);
            }
        },
    };

    info!("Found {} authorized keys", authorized_keys.len());

    if authorized_keys.is_empty() {
        error!("No authorized keys found");
        return Err(-5);
    }

    let context = Arc::new(routes::AppState {
        key_private: key_encrypt,
        key_public: key_encrypt_public,
        authorized_keys,
    });

    let app = Router::new()
        .route("/public", get(routes::public))
        .route("/request", post(routes::request))
        .with_state(context);

    let host = dotenv::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = dotenv::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("{}:{}", host, port);

    let listener = TcpListener::bind(&addr).await.unwrap();
    info!("Listening on {}", addr);

    let err = axum::serve(listener, app).await.unwrap_err();
    error!("Server error: {}", err);

    Ok(())
}
