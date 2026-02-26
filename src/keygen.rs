use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use crate::acme_client::{KeyType, RsaKeySize, EllipticCurve};

pub fn generate_csr_der_and_private_key_pem(
    subject_alt_names: Vec<String>,
    key_type: KeyType,
    rsa_key_size: RsaKeySize,
    elliptic_curve: EllipticCurve,
) -> Result<(Vec<u8>, String)> {
    let mut params = CertificateParams::new(subject_alt_names).context("Invalid subjectAltName")?;
    params.distinguished_name = DistinguishedName::new();

    let signing_key = match key_type {
        KeyType::Ecdsa => {
            let curve = match elliptic_curve {
                EllipticCurve::P256 => &rcgen::PKCS_ECDSA_P256_SHA256,
                EllipticCurve::P384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            };
            KeyPair::generate_for(curve).context("Failed to generate ECDSA key")?
        }
        KeyType::Rsa => {
            let bits = match rsa_key_size {
                RsaKeySize::R2048 => rcgen::RsaKeySize::_2048,
                RsaKeySize::R3072 => rcgen::RsaKeySize::_3072,
                RsaKeySize::R4096 => rcgen::RsaKeySize::_4096,
            };
            KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, bits).context("Failed to generate RSA key")?
        }
    };

    let csr = params.serialize_request(&signing_key).context("Failed to serialize CSR")?;
    
    Ok((csr.der().to_vec(), signing_key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_csr_and_key() {
        let (csr, key) = generate_csr_der_and_private_key_pem(
            vec!["example.com".to_string()],
            KeyType::Ecdsa,
            RsaKeySize::R2048,
            EllipticCurve::P256,
        ).unwrap();
        assert!(!csr.is_empty());
        assert!(key.contains("PRIVATE KEY"));
        
        // Test RSA as well
        let (csr, key) = generate_csr_der_and_private_key_pem(
            vec!["example.com".to_string()],
            KeyType::Rsa,
            RsaKeySize::R2048,
            EllipticCurve::P256,
        ).unwrap();
        assert!(!csr.is_empty());
        assert!(key.contains("PRIVATE KEY"));
    }
}
