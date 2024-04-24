extern crate rcgen;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P384_SHA384};

use std::{fmt::Debug, io, path::PathBuf};

use time::{OffsetDateTime, UtcOffset};

use crate::utils::print_error;

pub enum LoadCertError {
    FileLoadError(io::Error),
    CreateKeyPairError(rcgen::Error),
    CreateCertificateParamError(rcgen::Error),
    CreateCertificateError(rcgen::Error),
    CreateRustlsConfigError(io::Error),
}

impl Debug for LoadCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadCertError::FileLoadError(err) => {
                print_error(f, "Failed to load certificate and key file", err)
            }
            LoadCertError::CreateKeyPairError(err) => {
                print_error(f, "Failed to create key pair", err)
            }
            LoadCertError::CreateCertificateParamError(err) => {
                print_error(f, "Failed to create certificate params", err)
            }
            LoadCertError::CreateCertificateError(err) => {
                print_error(f, "Failed to create certificate", err)
            }
            LoadCertError::CreateRustlsConfigError(err) => {
                print_error(f, "Failed to create RustlsConfig", err)
            }
        }
    }
}

pub async fn load_or_create_cert() -> Result<RustlsConfig, LoadCertError> {
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
                return Err(LoadCertError::FileLoadError(err));
            }
        };
        return Ok(config);
    }

    let key_pair = match KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384) {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadCertError::CreateKeyPairError(err));
        }
    };

    let mut cert_params = match CertificateParams::new(vec!["localhost".to_string()]) {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadCertError::CreateCertificateParamError(err));
        }
    };

    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "LDAP-REST Bridge".to_string());
    dn.push(DnType::CommonName, "localhost".to_string());
    cert_params.distinguished_name = dn;

    cert_params.not_before = OffsetDateTime::from_unix_timestamp(chrono::Utc::now().timestamp())
        .unwrap()
        .to_offset(UtcOffset::UTC);
    cert_params.not_after = OffsetDateTime::from_unix_timestamp(
        (chrono::Utc::now() + chrono::Duration::days(365)).timestamp(),
    )
    .unwrap()
    .to_offset(UtcOffset::UTC);

    let cert = match cert_params.self_signed(&key_pair) {
        Ok(val) => val,
        Err(err) => {
            return Err(LoadCertError::CreateCertificateError(err));
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
            return Err(LoadCertError::CreateRustlsConfigError(err));
        }
    };

    Ok(config)
}
