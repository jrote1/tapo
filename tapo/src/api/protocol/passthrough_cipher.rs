use base64::{engine::general_purpose, Engine as _};
use log::debug;

use rsa::{pkcs8::EncodePublicKey, pkcs1::DecodeRsaPrivateKey, RsaPrivateKey, Pkcs1v15Encrypt, PublicKeyParts};
use sha1::{Sha1,Digest};

use super::encryption_helpers::{decrypt_aes_128_cbc, encrypt_aes_128_cbc};

#[derive(Debug, Clone)]
pub(crate) struct PassthroughKeyPair {
    rsa: rsa::RsaPrivateKey,
}

impl PassthroughKeyPair {
    pub fn new() -> anyhow::Result<Self> {
        debug!("Generating RSA key pair...");
        
        let mut rng = rand::thread_rng();
        let rsa = rsa::RsaPrivateKey::new(&mut rng, 1024)?;

        Ok(Self { rsa })
    }

    pub fn get_public_key(&self) -> anyhow::Result<String> {
        let public_key_pem = self.rsa.to_public_key().to_public_key_pem(rsa::pkcs8::LineEnding::CRLF)?;
        let public_key = std::str::from_utf8(&public_key_pem.as_bytes())?.to_string();

        Ok(public_key)
    }
}

#[derive(Debug)]
pub(crate) struct PassthroughCipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl PassthroughCipher {
    pub fn new(key: &str, key_pair: &PassthroughKeyPair) -> anyhow::Result<Self> {
        debug!("Will decode handshake key {:?}...", &key[..5]);

        let key_bytes = general_purpose::STANDARD.decode(key)?;
        let mut buf = vec![0; key_pair.rsa.size() as usize];

        let private_key = RsaPrivateKey::from_pkcs1_pem(&String::from_utf8(key_bytes).unwrap())?;

        let decrypt_count = private_key.decrypt(Pkcs1v15Encrypt, &buf)?.len();

        if decrypt_count != 32 {
            return Err(anyhow::anyhow!("expected 32 bytes, got {decrypt_count}"));
        }

        Ok(PassthroughCipher {
            key: buf[0..16].to_vec(),
            iv: buf[16..32].to_vec(),
        })
    }

    pub fn encrypt(&self, data: &str) -> anyhow::Result<String> {
        let cipher_bytes = encrypt_aes_128_cbc(data.as_bytes(), &self.key,&self.iv);
        let cipher_base64 = general_purpose::STANDARD.encode(cipher_bytes);

        Ok(cipher_base64)
    }

    pub fn decrypt(&self, cipher_base64: &str) -> anyhow::Result<String> {
        let cipher_bytes = general_purpose::STANDARD.decode(cipher_base64)?;
        let decrypted_bytes = decrypt_aes_128_cbc(&cipher_bytes, &self.key, &self.iv);
        let decrypted = std::str::from_utf8(&decrypted_bytes)?.to_string();

        Ok(decrypted)
    }
}

impl PassthroughCipher {
    pub fn sha1_digest_username(username: String) -> String {
        let mut hasher = Sha1::new();
        hasher.update(username.as_bytes());
        String::from_utf8(hasher.finalize()[..].to_vec()).unwrap()
    }
}
