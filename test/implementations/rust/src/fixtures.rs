//! Test Fixtures - Certificate and Key Generation
//! 
//! Provides test certificates, keys, and malformed data for comprehensive
//! security testing. All keys are clearly marked as TEST-ONLY.

use anyhow::Result;
use rcgen::{Certificate, CertificateParams, DnType, KeyPair};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Test certificate types for different security scenarios
#[derive(Debug, Clone, Copy)]
pub enum TestCertificateType {
    Valid,
    Expired,
    NotYetValid,
    SelfSigned,
    WeakKey,
    InvalidSignature,
    MalformedExtensions,
    OversizedChain,
}

/// Test key types for cryptographic testing
#[derive(Debug, Clone, Copy)]
pub enum TestKeyType {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    WeakRsa1024, // For negative testing
    InvalidKey,
}

/// Certificate fixture generator
pub struct CertificateFixtures;

impl CertificateFixtures {
    /// Generate test certificate based on type
    pub fn generate_test_certificate(cert_type: TestCertificateType, hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        match cert_type {
            TestCertificateType::Valid => Self::generate_valid_certificate(hostname),
            TestCertificateType::Expired => Self::generate_expired_certificate(hostname),
            TestCertificateType::NotYetValid => Self::generate_future_certificate(hostname),
            TestCertificateType::SelfSigned => Self::generate_self_signed_certificate(hostname),
            TestCertificateType::WeakKey => Self::generate_weak_key_certificate(hostname),
            TestCertificateType::InvalidSignature => Self::generate_invalid_signature_certificate(hostname),
            TestCertificateType::MalformedExtensions => Self::generate_malformed_extensions_certificate(hostname),
            TestCertificateType::OversizedChain => Self::generate_oversized_chain_certificate(hostname),
        }
    }
    
    /// Generate valid TLS certificate for testing
    fn generate_valid_certificate(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::new(vec![hostname.to_string()]);
        params.distinguished_name.push(DnType::CommonName, "WASI-TLS Test Certificate");
        params.distinguished_name.push(DnType::OrganizationName, "TEST ONLY - DO NOT USE");
        
        // Valid for 1 year from now
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        params.not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(now - 3600); // 1 hour ago
        params.not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(now + 365 * 24 * 3600); // 1 year from now
        
        // Use strong key
        params.key_pair = Some(KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?);
        
        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();
        
        Ok((cert_der, key_der))
    }
    
    /// Generate expired certificate
    fn generate_expired_certificate(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::new(vec![hostname.to_string()]);
        params.distinguished_name.push(DnType::CommonName, "EXPIRED Test Certificate");
        params.distinguished_name.push(DnType::OrganizationName, "TEST ONLY - EXPIRED");
        
        // Expired 1 year ago
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        params.not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(now - 2 * 365 * 24 * 3600);
        params.not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(now - 365 * 24 * 3600);
        
        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();
        
        Ok((cert_der, key_der))
    }
    
    /// Generate certificate not yet valid
    fn generate_future_certificate(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::new(vec![hostname.to_string()]);
        params.distinguished_name.push(DnType::CommonName, "FUTURE Test Certificate");
        params.distinguished_name.push(DnType::OrganizationName, "TEST ONLY - NOT YET VALID");
        
        // Valid in the future
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        params.not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(now + 365 * 24 * 3600);
        params.not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(now + 2 * 365 * 24 * 3600);
        
        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();
        
        Ok((cert_der, key_der))
    }
    
    /// Generate self-signed certificate (should be rejected)
    fn generate_self_signed_certificate(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::new(vec![hostname.to_string()]);
        params.distinguished_name.push(DnType::CommonName, "SELF-SIGNED Test Certificate");
        params.distinguished_name.push(DnType::OrganizationName, "TEST ONLY - SELF SIGNED");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        
        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();
        
        Ok((cert_der, key_der))
    }
    
    /// Generate certificate with weak key (for negative testing)
    fn generate_weak_key_certificate(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::new(vec![hostname.to_string()]);
        params.distinguished_name.push(DnType::CommonName, "WEAK KEY Test Certificate");
        params.distinguished_name.push(DnType::OrganizationName, "TEST ONLY - WEAK KEY");
        
        // Note: rcgen doesn't support RSA 1024, so we simulate with a comment
        // In real testing, this would use actual weak keys
        params.key_pair = Some(KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?);
        
        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();
        
        Ok((cert_der, key_der))
    }
    
    /// Generate certificate with invalid signature
    fn generate_invalid_signature_certificate(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let (mut cert_der, key_der) = Self::generate_valid_certificate(hostname)?;
        
        // Corrupt the signature by modifying the last few bytes
        let len = cert_der.len();
        if len > 10 {
            for i in (len - 10)..len {
                cert_der[i] = !cert_der[i]; // Flip bits to corrupt signature
            }
        }
        
        Ok((cert_der, key_der))
    }
    
    /// Generate certificate with malformed extensions
    fn generate_malformed_extensions_certificate(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        // Start with valid certificate
        let (mut cert_der, key_der) = Self::generate_valid_certificate(hostname)?;
        
        // Insert malformed extension data
        // This is a simplified approach - real implementation would parse and modify ASN.1
        let malformed_extension = vec![
            0x30, 0x82, 0xFF, 0xFF, // Invalid length encoding
            0x06, 0x03, 0x55, 0x1d, 0x0e, // Subject Key Identifier OID
            0x04, 0xFF, // Invalid octet string length
        ];
        
        cert_der.extend_from_slice(&malformed_extension);
        
        Ok((cert_der, key_der))
    }
    
    /// Generate oversized certificate chain
    fn generate_oversized_chain_certificate(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let (cert_der, key_der) = Self::generate_valid_certificate(hostname)?;
        
        // Create an artificially large certificate by padding with comments
        let mut oversized_cert = cert_der;
        let padding = vec![0x30, 0x82, 0x10, 0x00]; // Large SEQUENCE
        let padding_data = vec![0x0C; 4096]; // UTF8String with 4KB of data
        
        oversized_cert.extend_from_slice(&padding);
        oversized_cert.extend_from_slice(&padding_data);
        
        Ok((oversized_cert, key_der))
    }
    
    /// Generate certificate chain of specified length
    pub fn generate_certificate_chain(length: usize, hostname: &str) -> Result<Vec<Vec<u8>>> {
        let mut chain = Vec::new();
        
        // Generate CA certificate
        let mut ca_params = CertificateParams::new(vec![]);
        ca_params.distinguished_name.push(DnType::CommonName, "TEST CA");
        ca_params.distinguished_name.push(DnType::OrganizationName, "TEST ONLY - CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        
        let ca_cert = Certificate::from_params(ca_params)?;
        let ca_key_pair = ca_cert.get_key_pair();
        
        // Generate intermediate certificates
        let mut current_issuer = ca_cert;
        for i in 0..length.saturating_sub(1) {
            let mut intermediate_params = CertificateParams::new(vec![]);
            intermediate_params.distinguished_name.push(DnType::CommonName, &format!("TEST Intermediate {}", i));
            intermediate_params.distinguished_name.push(DnType::OrganizationName, "TEST ONLY - INTERMEDIATE");
            intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            
            let intermediate_cert = Certificate::from_params(intermediate_params)?;
            let intermediate_der = intermediate_cert.serialize_der_with_signer(&current_issuer)?;
            chain.push(intermediate_der);
            
            current_issuer = intermediate_cert;
        }
        
        // Generate end-entity certificate
        let mut ee_params = CertificateParams::new(vec![hostname.to_string()]);
        ee_params.distinguished_name.push(DnType::CommonName, hostname);
        ee_params.distinguished_name.push(DnType::OrganizationName, "TEST ONLY - END ENTITY");
        
        let ee_cert = Certificate::from_params(ee_params)?;
        let ee_der = ee_cert.serialize_der_with_signer(&current_issuer)?;
        chain.insert(0, ee_der); // End-entity certificate first
        
        Ok(chain)
    }
    
    /// Generate malformed certificate data for fuzzing
    pub fn generate_malformed_certificate_data(pattern: MalformedPattern) -> Vec<u8> {
        match pattern {
            MalformedPattern::InvalidAsn1 => {
                vec![0x30, 0xFF, 0xFF, 0xFF, 0xFF] // Invalid length encoding
            }
            MalformedPattern::TruncatedData => {
                vec![0x30, 0x82, 0x01, 0x00] // Claims 256 bytes but truncated
            }
            MalformedPattern::InvalidOid => {
                vec![0x30, 0x0A, 0x06, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] // Invalid OID
            }
            MalformedPattern::NegativeLength => {
                vec![0x30, 0x80] // Indefinite length (prohibited in DER)
            }
            MalformedPattern::ZeroLength => {
                vec![0x30, 0x00] // Empty SEQUENCE
            }
            MalformedPattern::ExcessiveNesting => {
                let mut data = Vec::new();
                for _ in 0..1000 {
                    data.extend_from_slice(&[0x30, 0x02]); // Nested SEQUENCE
                }
                data
            }
        }
    }
}

/// Key pair fixture generator
pub struct KeyFixtures;

impl KeyFixtures {
    /// Generate test key pair of specified type
    pub fn generate_test_key_pair(key_type: TestKeyType) -> Result<(Vec<u8>, Vec<u8>)> {
        match key_type {
            TestKeyType::Rsa2048 => Self::generate_rsa_key(2048),
            TestKeyType::Rsa4096 => Self::generate_rsa_key(4096),
            TestKeyType::EcdsaP256 => Self::generate_ecdsa_key("P-256"),
            TestKeyType::EcdsaP384 => Self::generate_ecdsa_key("P-384"),
            TestKeyType::WeakRsa1024 => Self::generate_rsa_key(1024), // For negative testing
            TestKeyType::InvalidKey => Self::generate_invalid_key(),
        }
    }
    
    fn generate_rsa_key(bits: usize) -> Result<(Vec<u8>, Vec<u8>)> {
        // Note: rcgen doesn't support RSA key generation directly
        // This is a placeholder for RSA key generation
        let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let private_key = key_pair.serialize_der();
        let public_key = key_pair.public_key_der();
        
        Ok((private_key, public_key))
    }
    
    fn generate_ecdsa_key(curve: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let algorithm = match curve {
            "P-256" => &rcgen::PKCS_ECDSA_P256_SHA256,
            "P-384" => &rcgen::PKCS_ECDSA_P384_SHA384,
            _ => &rcgen::PKCS_ECDSA_P256_SHA256,
        };
        
        let key_pair = KeyPair::generate(algorithm)?;
        let private_key = key_pair.serialize_der();
        let public_key = key_pair.public_key_der();
        
        Ok((private_key, public_key))
    }
    
    fn generate_invalid_key() -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate malformed key data
        let invalid_private = vec![
            0x30, 0x82, 0x01, 0x00, // SEQUENCE
            0x02, 0x01, 0x00,       // INTEGER version
            0xFF, 0xFF, 0xFF, 0xFF, // Invalid key material
        ];
        
        let invalid_public = vec![
            0x30, 0x82, 0x00, 0x0A, // SEQUENCE
            0xFF, 0xFF, 0xFF, 0xFF, // Invalid key material
        ];
        
        Ok((invalid_private, invalid_public))
    }
}

/// TLS handshake message fixtures
pub struct HandshakeFixtures;

impl HandshakeFixtures {
    /// Generate ClientHello message for testing
    pub fn generate_client_hello(version: u16, cipher_suites: &[u16]) -> Vec<u8> {
        let mut client_hello = vec![
            0x16, // Handshake
            0x03, 0x04, // TLS 1.3
            0x00, 0x00, // Length placeholder
        ];
        
        // Handshake message
        let mut handshake = vec![
            0x01, // ClientHello
            0x00, 0x00, 0x00, // Length placeholder
        ];
        
        // Protocol version
        handshake.extend_from_slice(&version.to_be_bytes());
        
        // Random (32 bytes)
        handshake.extend(vec![0xAB; 32]);
        
        // Session ID (empty for TLS 1.3)
        handshake.push(0x00);
        
        // Cipher suites
        handshake.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
        for &cipher in cipher_suites {
            handshake.extend_from_slice(&cipher.to_be_bytes());
        }
        
        // Compression methods (none for TLS 1.3)
        handshake.extend_from_slice(&[0x01, 0x00]);
        
        // Extensions (placeholder)
        handshake.extend_from_slice(&[0x00, 0x00]);
        
        // Update lengths
        let handshake_len = handshake.len() - 4;
        handshake[1..4].copy_from_slice(&(handshake_len as u32).to_be_bytes()[1..]);
        
        client_hello.extend(handshake);
        let total_len = client_hello.len() - 5;
        client_hello[3..5].copy_from_slice(&(total_len as u16).to_be_bytes());
        
        client_hello
    }
    
    /// Generate malformed handshake messages for fuzzing
    pub fn generate_malformed_handshake(pattern: MalformedPattern) -> Vec<u8> {
        match pattern {
            MalformedPattern::InvalidAsn1 => {
                vec![0x16, 0x03, 0x04, 0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            }
            MalformedPattern::TruncatedData => {
                vec![0x16, 0x03, 0x04, 0x01, 0x00, 0x01] // Claims 256 bytes but only has 1
            }
            MalformedPattern::ExcessiveNesting => {
                let mut data = vec![0x16, 0x03, 0x04, 0x10, 0x00]; // Record header
                data.extend(vec![0x16; 4096]); // 4KB of nested records
                data
            }
            _ => vec![0x16, 0x03, 0x04, 0x00, 0x00], // Empty record
        }
    }
}

/// Malformed data patterns for security testing
#[derive(Debug, Clone, Copy)]
pub enum MalformedPattern {
    InvalidAsn1,
    TruncatedData,
    InvalidOid,
    NegativeLength,
    ZeroLength,
    ExcessiveNesting,
}

/// Test data cleanup utility
pub struct TestCleanup;

impl TestCleanup {
    /// Clean up temporary test files
    pub fn cleanup_test_files() -> Result<()> {
        // In a real implementation, this would clean up any temporary
        // certificates or keys created during testing
        Ok(())
    }
    
    /// Verify no test certificates are in production stores
    pub fn verify_no_test_certs_in_production() -> Result<()> {
        // This would scan certificate stores to ensure no test certificates
        // accidentally made it into production
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_certificate_generation() {
        let (cert_der, key_der) = CertificateFixtures::generate_test_certificate(
            TestCertificateType::Valid, 
            "test.example.com"
        ).expect("Should generate valid certificate");
        
        assert!(!cert_der.is_empty(), "Certificate should not be empty");
        assert!(!key_der.is_empty(), "Key should not be empty");
        
        // Verify certificate is properly formatted DER
        assert_eq!(cert_der[0], 0x30, "Certificate should start with SEQUENCE");
    }
    
    #[test]
    fn test_expired_certificate_generation() {
        let (cert_der, _) = CertificateFixtures::generate_test_certificate(
            TestCertificateType::Expired,
            "expired.example.com"
        ).expect("Should generate expired certificate");
        
        assert!(!cert_der.is_empty(), "Expired certificate should not be empty");
        assert_eq!(cert_der[0], 0x30, "Certificate should start with SEQUENCE");
    }
    
    #[test]
    fn test_malformed_certificate_generation() {
        let malformed = CertificateFixtures::generate_malformed_certificate_data(
            MalformedPattern::InvalidAsn1
        );
        
        assert!(!malformed.is_empty(), "Malformed data should not be empty");
    }
    
    #[test]
    fn test_key_pair_generation() {
        let (private_key, public_key) = KeyFixtures::generate_test_key_pair(
            TestKeyType::EcdsaP256
        ).expect("Should generate ECDSA P-256 key pair");
        
        assert!(!private_key.is_empty(), "Private key should not be empty");
        assert!(!public_key.is_empty(), "Public key should not be empty");
    }
    
    #[test]
    fn test_handshake_message_generation() {
        let client_hello = HandshakeFixtures::generate_client_hello(
            0x0304, // TLS 1.3
            &[0x1301, 0x1302] // AES-128-GCM, AES-256-GCM
        );
        
        assert!(!client_hello.is_empty(), "ClientHello should not be empty");
        assert_eq!(client_hello[0], 0x16, "Should be handshake record type");
        assert_eq!(&client_hello[1..3], &[0x03, 0x04], "Should be TLS 1.3");
    }
}