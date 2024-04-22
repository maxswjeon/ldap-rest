extern crate rcgen;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};

use std::{fmt::Debug, io, path::PathBuf};

use crate::utils::print_error;

pub enum LoadError {
    FileLoadError(io::Error),
    CreateKeyPairError(rcgen::Error),
    CreateCertificateParamError(rcgen::Error),
    CreateCertificateError(rcgen::Error),
    CreateRustlsConfigError(io::Error),
}

impl Debug for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::FileLoadError(err) => {
                print_error(f, "Failed to load certificate and key file", err)
            }
            LoadError::CreateKeyPairError(err) => print_error(f, "Failed to create key pair", err),
            LoadError::CreateCertificateParamError(err) => {
                print_error(f, "Failed to create certificate params", err)
            }
            LoadError::CreateCertificateError(err) => {
                print_error(f, "Failed to create certificate", err)
            }
            LoadError::CreateRustlsConfigError(err) => {
                print_error(f, "Failed to create RustlsConfig", err)
            }
        }
    }
}

pub async fn load_or_create_cert() -> Result<RustlsConfig, LoadError> {
    let cert_path = match dotenv::var("CERT_PATH") {
        Ok(val) => Some(val),
        Err(_) => {
            tracing::info!("CERT_PATH not set");
            None
        }
    };

    let key_path = match dotenv::var("KEY_PATH") {
        Ok(val) => Some(val),
        Err(_) => {
            tracing::info!("KEY_PATH not set");
            None
        }
    };

    if cert_path.is_some() && key_path.is_some() {
        let config = match RustlsConfig::from_pem_file(
            PathBuf::from(cert_path.unwrap()),
            PathBuf::from(key_path.unwrap()),
        )
        .await
        {
            Ok(val) => val,
            Err(err) => {
                return Err(LoadError::FileLoadError(err));
            }
        };
        return Ok(config);
    }

    let key_pair = match KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384) {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadError::CreateKeyPairError(err));
        }
    };

    let cert_params = match CertificateParams::new(vec!["localhost".to_string()]) {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadError::CreateCertificateParamError(err));
        }
    };

    let cert = match cert_params.self_signed(&key_pair) {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadError::CreateCertificateError(err));
        }
    };

    tracing::info!("Generated self-signed certificate\n{}", cert.pem());

    let config = match RustlsConfig::from_pem(
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    )
    .await
    {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadError::CreateRustlsConfigError(err));
        }
    };

    Ok(config)
}
