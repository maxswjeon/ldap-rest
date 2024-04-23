mod config;
mod routes;
mod utils;

extern crate dotenv;

use std::net::AddrParseError;
use std::process::exit;
use std::{io, net::SocketAddr};

use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use clap::{Parser, Subcommand};
use p521::SecretKey;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
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
    Start(StartError),
    Generate(GenerateError),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Start(err) => write!(f, "{:?}", err),
            Error::Generate(err) => write!(f, "{:?}", err),
        }
    }
}

enum StartError {
    CreateSignalHandlerError(io::Error),
    AddressParseError(AddrParseError),
    CertificateError(config::LoadError),
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
            StartError::AddressParseError(err) => {
                utils::print_error(f, "Failed to parse address, exiting.", err)
            }
            StartError::ServerError(err) => {
                utils::print_error(f, "Error occurred while running server, exiting", err)
            }
        }
    }
}

enum GenerateError {
    KeyPairError(config::LoadError),
    CertificateParamError(config::LoadError),
    CertificateError(config::LoadError),
}

impl std::fmt::Debug for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateError::KeyPairError(err) => {
                utils::print_error(f, "Failed to generate key pair, exiting.", err)
            }
            GenerateError::CertificateParamError(err) => {
                utils::print_error(f, "Failed to generate certificate params, exiting.", err)
            }
            GenerateError::CertificateError(err) => {
                utils::print_error(f, "Failed to generate certificate, exiting.", err)
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "LDAP - REST Bridge",
    long_about = "Secure LDAP client that exposes a REST API"
)]
struct Arguments {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Start,
    Genkey { name: String, force: Option<bool> },
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

    let args = Arguments::parse();

    let command = match args.command {
        Some(val) => val,
        None => Commands::Start,
    };

    let res = match command {
        Commands::Start => start().await,
        Commands::Genkey { name, force } => genkey(name, force.unwrap_or_else(|| false)).await,
    };

    match res {
        Ok(_) => Ok(()),
        Err(err) => {
            tracing::error!("{:?}", err);
            Err(())
        }
    }
}

async fn genkey(name: String, force: bool) -> Result<(), Error> {
    let mut rng = ChaCha20Rng::from_entropy();
    let key_secret = SecretKey::random(&mut rng);
    let key_public = key_secret.public_key();

    Ok(())
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

    let app = Router::new()
        .route("/", get(routes::index))
        .route("/request", post(routes::request));

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

    tokio::spawn(signal_reload(signals_reload, conf.clone()));
    tokio::spawn(signal_shutdown(signals_shutdown, handle.clone()));

    let server = axum_server::bind_rustls(addr, conf);
    tracing::info!("Listening on {}", addr);

    match server.handle(handle).serve(app.into_make_service()).await {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::Start(StartError::ServerError(err))),
    }
}

async fn signal_reload(mut signals: SignalsInfo, config: RustlsConfig) {
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

async fn signal_shutdown(mut signals: SignalsInfo, handle: Handle) {
    for sig in signals.forever() {
        tracing::info!("Received signal {:?}", sig);
        tracing::info!("Shutting down server");
        handle.shutdown();
        exit(0)
    }
}
