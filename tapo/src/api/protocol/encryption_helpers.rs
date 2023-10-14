use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyIvInit};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;


pub fn encrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut buf_alt = data.to_vec();
    buf_alt.resize(data.len() * 2, 0);

    let result = Aes128CbcEnc::new(key.into(), iv.into()).encrypt_padded_mut::<Pkcs7>(&mut buf_alt, data.len());

    result.unwrap().to_vec()
}

pub fn decrypt_aes_128_cbc(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut buf = encrypted_data.to_vec();

    Aes128CbcDec::new(key.into(), iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buf).unwrap().to_vec()
}
