use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use cbc::{Decryptor, Encryptor};
use rand::{RngExt, rng};
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rng().fill(&mut iv[..]);
    iv
}

pub fn encrypt_payload(data: &[u8], key: &[u8; 32]) -> String {
    let iv = generate_iv();
    let pt_len = data.len();
    let mut buf = vec![0u8; pt_len + 16];
    buf[..pt_len].copy_from_slice(data);
    let ct = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(ct);
    STANDARD.encode(&out)
}

pub fn decrypt_payload(b64_data: &str, key: &[u8; 32]) -> Result<Vec<u8>, anyhow::Error> {
    let raw = STANDARD.decode(b64_data)?;
    if raw.len() < 16 {
        return Err(anyhow::anyhow!("Payload too short"));
    }
    let (iv, ct) = raw.split_at(16);
    let mut buf = ct.to_vec();
    let iv_arr: &[u8; 16] = iv.try_into().unwrap();
    let pt = Aes256CbcDec::new(key.into(), iv_arr.into())
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("Decrypt error: {:?}", e))?;
    Ok(pt.to_vec())
}
