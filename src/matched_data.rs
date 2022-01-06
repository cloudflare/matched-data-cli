use bincode::ErrorKind;
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    setup_receiver, Deserializable, HpkeError, Kem as KemTrait, OpModeR,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

type PrivateKey = <Kem as KemTrait>::PrivateKey;
type PublicKey = <Kem as KemTrait>::PublicKey;
type EncappedKey = <Kem as KemTrait>::EncappedKey;

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    encapped_key: EncappedKey,
    ciphertext: Vec<u8>,
    tag: AeadTag<Aead>,
}

// Generates a public-private key pair
pub fn generate_key_pair() -> (PrivateKey, PublicKey) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}

// Constructs a PrivateKey from an array of bytes
pub fn get_private_key_from_bytes(private_key_bytes: &[u8]) -> Result<PrivateKey, HpkeError> {
    PrivateKey::from_bytes(private_key_bytes)
}

// Decrypts data with provided private key
pub fn decrypt_data(
    encrypted_data: &EncryptedData,
    private_key: &PrivateKey,
) -> Result<Vec<u8>, HpkeError> {
    // Decapsulate and derive the shared secret. Create a shared AEAD context.
    let mut aead_ctx = setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        private_key,
        &encrypted_data.encapped_key,
        &[],
    )?;

    // Decrypt ciphertext in place
    let mut ciphertext_copy = encrypted_data.ciphertext.clone();
    aead_ctx.open_in_place_detached(&mut ciphertext_copy, &[], &encrypted_data.tag)?;

    // Rename for clarity
    let plaintext = ciphertext_copy;

    Ok(plaintext)
}

// Deserializes an array of bytes using bincode into encrypted data
pub fn deserialize_encrypted_data(
    serialized_encrypted_data: &[u8],
) -> Result<EncryptedData, Box<ErrorKind>> {
    bincode::deserialize(&serialized_encrypted_data[1..])
}
