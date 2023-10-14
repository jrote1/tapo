use std::fmt;

use async_trait::async_trait;
use log::debug;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use reqwest::Client;
use serde::de::DeserializeOwned;

use crate::requests::TapoRequest;
use crate::responses::{validate_response, TapoResponse, TapoResponseExt};
use crate::Error;

use super::discovery_protocol::DiscoveryProtocol;
use super::klap_cipher::KlapCipher;
use super::TapoProtocolExt;

#[derive(Debug)]
pub(crate) struct KlapProtocol {
    client: Client,
    username: String,
    password: String,
    rng: StdRng,
    url: Option<String>,
    cipher: Option<KlapCipher>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl TapoProtocolExt for KlapProtocol {
    async fn login(&mut self, url: String) -> Result<(), Error> {
        self.handshake(url).await?;
        Ok(())
    }

    async fn refresh_session(&mut self) -> Result<(), Error> {
        let url = self.url.as_ref().expect("This should never happen").clone();
        self.handshake(url).await?;
        Ok(())
    }

    async fn execute_request<R>(
        &self,
        request: TapoRequest,
        _with_token: bool,
    ) -> Result<Option<R>, Error>
    where
        R: fmt::Debug + DeserializeOwned + TapoResponseExt,
    {
        let url = self.url.as_ref().expect("This should never happen");
        let cipher = self.get_cipher_ref();

        let request_string = serde_json::to_string(&request)?;
        debug!("Request to passthrough: {request_string}");

        let (payload, seq) = cipher.encrypt(request_string)?;

        let request = self.client.post(format!("{url}/request?seq={seq}"))
            .body(payload);

        let response = request
            .send()
            .await?
            .bytes()
            .await
            .map_err(anyhow::Error::from)?;

        let response_decrypted = cipher.decrypt(seq, response.to_vec())?;
        debug!("Device responded with: {response_decrypted:?}");

        let inner_response: TapoResponse<R> = serde_json::from_str(&response_decrypted)?;
        debug!("Device inner response: {inner_response:?}");

        validate_response(&inner_response)?;
        let result = inner_response.result;

        Ok(result)
    }

    fn clone_as_discovery(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::new(
            self.client.clone(),
            self.username.clone(),
            self.password.clone(),
        )
    }
}

impl KlapProtocol {
    pub fn new(client: Client, username: String, password: String) -> Self {
        Self {
            client,
            username,
            password,
            rng: StdRng::from_entropy(),
            url: None,
            cipher: None,
        }
    }

    async fn handshake(&mut self, url: String) -> Result<(), Error> {
        let auth_hash = KlapCipher::sha256(
            &[
                KlapCipher::sha1(self.username.as_bytes()),
                KlapCipher::sha1(self.password.as_bytes()),
            ]
            .concat(),
        )
        .to_vec();

        let mut local_seed = self.get_local_seed().to_vec();
        let remote_seed = self.handshake1(&url, &mut local_seed, &auth_hash).await?;

        self.handshake2(&url, &local_seed, &remote_seed, &auth_hash)
            .await?;

        let cipher = KlapCipher::new(local_seed, remote_seed, auth_hash)?;

        self.url.replace(url);
        self.cipher.replace(cipher);

        Ok(())
    }

    async fn handshake1(
        &self,
        url: &str,
        local_seed: &mut [u8],
        auth_hash: &[u8],
    ) -> Result<Vec<u8>, Error> {
        debug!("Performing handshake1...");
        let url = format!("{url}/handshake1");

        let request = self.client.post(&url)
            .body(local_seed.to_owned());

        let response = request
            .send()
            .await?
            .bytes()
            .await
            .map_err(anyhow::Error::from)?;

        let (remote_seed, server_hash) = response.split_at(16);

        let local_hash = KlapCipher::sha256(&[local_seed, remote_seed, auth_hash].concat());

        println!("{:?}", local_hash);
        println!("{:?}", server_hash);

        if local_hash != server_hash {
            return Err(anyhow::anyhow!("Local hash does not match server hash").into());
        }

        debug!("Handshake1 OK");

        Ok(remote_seed.to_vec())
    }

    async fn handshake2(
        &self,
        url: &str,
        local_seed: &[u8],
        remote_seed: &[u8],
        auth_hash: &[u8],
    ) -> Result<(), Error> {
        debug!("Performing handshake2...");
        let url = format!("{url}/handshake2");

        let payload = KlapCipher::sha256(
            &[remote_seed.clone(), local_seed.clone(), auth_hash.clone()].concat(),
        );

        let request = self.client.post(&url)
            .body(payload.to_vec());

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("").into());
        }

        debug!("Handshake2 OK");

        Ok(())
    }

    fn get_local_seed(&mut self) -> [u8; 16] {
        let mut buffer = [0u8; 16];
        self.rng.fill_bytes(&mut buffer);
        buffer
    }

    fn get_cipher_ref(&self) -> &KlapCipher {
        self.cipher.as_ref().expect("This should never happen")
    }
}
