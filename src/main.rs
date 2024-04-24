mod config;
mod routes;
mod types;
mod utils;

extern crate dotenv;

use std::net::AddrParseError;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, net::SocketAddr};

use axum::error_handling::HandleErrorLayer;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::{extract, BoxError};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use signal_hook::iterator::SignalsInfo;
use signal_hook::{
    consts::{SIGHUP, SIGUSR2},
    iterator::Signals,
};

use ssh_key::authorized_keys::Entry;
use ssh_key::AuthorizedKeys;
use tower::ServiceBuilder;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use axum::{
    routing::{get, post},
    Router,
};
use types::routes::Response;

enum Error {
    Start(StartError),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Start(err) => write!(f, "{:?}", err),
        }
    }
}

enum StartError {
    CreateSignalHandlerError(io::Error),
    AddressParseError(AddrParseError),
    CertificateError(config::LoadCertError),
    AuthorizedKeysError(ssh_key::Error),
    ServerError(io::Error),
}

impl std::fmt::Debug for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::CreateSignalHandlerError(err) => {
                utils::print_error(f, "Failed to create signal handler, exiting.", err)
            }
            StartError::CertificateError(err) => {
                utils::print_error(f, "Failed to load or create certificate, exiting.", err)
            }
            StartError::AuthorizedKeysError(err) => {
                utils::print_error(f, "Failed to load authorized keys, exiting.", err)
            }
            StartError::AddressParseError(err) => {
                utils::print_error(f, "Failed to parse address, exiting.", err)
            }
            StartError::ServerError(err) => {
                utils::print_error(f, "Error occurred while running server, exiting", err)
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ldap_rest=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let res = start().await;
    match res {
        Ok(_) => Ok(()),
        Err(err) => {
            tracing::error!("{:?}", err);
            Err(())
        }
    }
}

struct AppState {
    authorized_keys: Mutex<Vec<Entry>>,
}

async fn start() -> Result<(), Error> {
    let host = dotenv::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = dotenv::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr: SocketAddr = match format!("{}:{}", host, port).to_string().parse() {
        Ok(val) => val,
        Err(err) => {
            return Err(Error::Start(StartError::AddressParseError(err)));
        }
    };

    let conf = match config::load_or_create_cert().await {
        Ok(val) => val,
        Err(err) => {
            return Err(Error::Start(StartError::CertificateError(err)));
        }
    };

    let authorized_keys_path =
        dotenv::var("AUTHORIZED_KEYS_PATH").unwrap_or_else(|_| "authorized_keys".to_string());
    let keys = match AuthorizedKeys::read_file(authorized_keys_path) {
        Ok(val) => val,
        Err(err) => {
            return Err(Error::Start(StartError::AuthorizedKeysError(err)));
        }
    };

    let state = Arc::new(AppState {
        authorized_keys: Mutex::new(keys),
    });

    let app = Router::new()
        .route("/", get(routes::index::get))
        .route("/query", post(routes::query::post))
        .with_state(state.clone())
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_error))
                .timeout(Duration::from_secs(10)),
        );

    let handle = Handle::new();

    let signals_reload = match Signals::new(&[SIGHUP, SIGUSR2]) {
        Ok(val) => val,
        Err(err) => {
            return Err(Error::Start(StartError::CreateSignalHandlerError(err)));
        }
    };

    let signals_shutdown =
        match Signals::new(&[signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]) {
            Ok(val) => val,
            Err(err) => {
                return Err(Error::Start(StartError::CreateSignalHandlerError(err)));
            }
        };

    tokio::spawn(signal_reload(signals_reload, conf.clone(), state));
    tokio::spawn(signal_shutdown(signals_shutdown, handle.clone()));

    let server = axum_server::bind_rustls(addr, conf);
    tracing::info!("Listening on {}", addr);

    match server.handle(handle).serve(app.into_make_service()).await {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::Start(StartError::ServerError(err))),
    }
}

async fn signal_reload(mut signals: SignalsInfo, config: RustlsConfig, state: Arc<AppState>) {
    for sig in signals.forever() {
        tracing::info!("Received signal {:?}", sig);

        tracing::info!("Reloading authorized keys");
        let authorized_keys_path =
            dotenv::var("AUTHORIZED_KEYS_PATH").unwrap_or_else(|_| "authorized_keys".to_string());
        let keys = match AuthorizedKeys::read_file(authorized_keys_path) {
            Ok(val) => Some(val),
            Err(err) => {
                tracing::error!("Failed to reload authorized keys: {:?}", err);
                None
            }
        };
        if keys.is_some() {
            let mut val = match state.authorized_keys.try_lock() {
                Ok(val) => val,
                Err(_) => {
                    tracing::error!("Failed to acquire lock on authorized keys");
                    continue;
                }
            };

            val.clear();
            val.extend(keys.unwrap());
            tracing::info!("Authorized keys reloaded");
        }

        tracing::info!("Reloading certificates");
        match config::load_or_create_cert().await {
            Ok(val) => {
                tracing::info!("Certificates reloaded");
                config.reload_from_config(val.get_inner());
            }
            Err(err) => {
                tracing::error!("Failed to reload certificates: {:?}", err);
            }
        };
    }
}

async fn signal_shutdown(mut signals: SignalsInfo, handle: Handle) {
    for sig in signals.forever() {
        tracing::info!("Received signal {:?}", sig);
        tracing::info!("Shutting down server");
        handle.shutdown();
        exit(0)
    }
}

async fn handle_error(err: BoxError) -> Response {
    if err.is::<tower::timeout::error::Elapsed>() {
        Response {
            status: StatusCode::REQUEST_TIMEOUT,
            body: Box::new(types::routes::ErrorResponse {
                result: false,
                message: "Request timed out".to_string(),
            }),
        }
    } else {
        Response {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: Box::new(types::routes::ErrorResponse {
                result: false,
                message: "Internal server error".to_string(),
            }),
        }
    }
}
