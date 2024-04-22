mod config;
mod routes;
mod utils;

extern crate dotenv;

use std::net::AddrParseError;
use std::{io, net::SocketAddr};

use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use signal_hook::iterator::SignalsInfo;
use signal_hook::{
    consts::{SIGHUP, SIGUSR2},
    iterator::Signals,
};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use axum::{
    routing::{get, post},
    Router,
};

enum Error {
    CreateSignalHandlerError(io::Error),
    AddressParseError(AddrParseError),
    CertificateError(config::LoadError),
    ServerError(io::Error),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CreateSignalHandlerError(err) => {
                utils::print_error(f, "Failed to create signal handler, exiting.", err)
            }
            Error::CertificateError(err) => {
                utils::print_error(f, "Failed to load or create certificate, exiting.", err)
            }
            Error::AddressParseError(err) => {
                utils::print_error(f, "Failed to parse address, exiting.", err)
            }
            Error::ServerError(err) => {
                utils::print_error(f, "Error occurred while running server, exiting", err)
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ldap_rest=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let host = dotenv::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = dotenv::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr: SocketAddr = match format!("{}:{}", host, port).to_string().parse() {
        Ok(val) => val,
        Err(err) => {
            return Err(Error::AddressParseError(err));
        }
    };

    let conf = match config::load_or_create_cert().await {
        Ok(val) => val,
        Err(err) => {
            return Err(Error::CertificateError(err));
        }
    };

    let signals = match Signals::new(&[SIGHUP, SIGUSR2]) {
        Ok(val) => val,
        Err(err) => {
            return Err(Error::CreateSignalHandlerError(err));
        }
    };

    let app = Router::new()
        .route("/", get(routes::index))
        .route("/request", post(routes::request));

    let handle = Handle::new();

    tokio::spawn(signal_handle(conf.clone(), signals));

    let server = axum_server::bind_rustls(addr, conf);
    tracing::info!("Listening on {}", addr);

    match server.handle(handle).serve(app.into_make_service()).await {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::ServerError(err)),
    }
}

async fn signal_handle(config: RustlsConfig, mut signals: SignalsInfo) {
    for sig in signals.forever() {
        tracing::info!("Received signal {:?}", sig);
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
