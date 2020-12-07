use hpke::kex::Serializable;
use matched_data::{
    decrypt_data, deserialize_encrypted_data, generate_key_pair, get_private_key_from_bytes,
    KeyPair,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn decrypt(private_key: &str, matched_data: &str) -> String {
    let private_key_bytes = radix64::STD
        .decode(&private_key)
        .expect("Cannot decode private key");
    let private_key =
        get_private_key_from_bytes(&private_key_bytes).expect("Failed to get private key");

    let encrypted_matched_data_bytes = radix64::STD
        .decode(&matched_data)
        .expect("Cannot decode matched data");
    let encrypted_matched_data = deserialize_encrypted_data(&encrypted_matched_data_bytes)
        .expect("Deserializing encrypted data failed");

    let matched_data =
        decrypt_data(&encrypted_matched_data, &private_key).expect("Failed to decrypt");

    return String::from_utf8_lossy(&matched_data).to_string();
}

#[wasm_bindgen]
pub fn keypair() -> JsValue {
    let (private_key, public_key) = generate_key_pair();

    let key_pair = KeyPair {
        private_key: radix64::STD.encode(&private_key.to_bytes()),
        public_key: radix64::STD.encode(&public_key.to_bytes()),
    };

    JsValue::from_serde(&key_pair).unwrap()
}
