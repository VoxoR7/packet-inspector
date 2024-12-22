use std::{fmt::Display, hash::Hash};

#[derive(Debug, PartialEq, Clone, Copy)]
enum SignatureWay {
    Unknow,
    Normal,
    Inverted,
}

#[derive(Debug)]
pub struct Signature {
    signature_way: SignatureWay,
    signature: Vec<u8>,
    protocol_path: String,
}

impl Signature {
    pub fn new() -> Self {
        Self {
            signature_way: SignatureWay::Unknow,
            signature: Vec::with_capacity(128),
            protocol_path: String::with_capacity(64),
        }
    }

    pub fn add_signature_one_way(&mut self, sign: &[u8]) {
        self.signature.extend_from_slice(sign);
    }

    pub fn add_signature_two_way(&mut self, sign_1: &[u8], sign_2: &[u8]) {
        if self.signature_way == SignatureWay::Unknow {
            if sign_1 < sign_2 {
                self.signature.push(0);
                self.signature_way = SignatureWay::Normal;
            } else {
                self.signature.push(1);
                self.signature_way = SignatureWay::Inverted;
            }
        }

        if self.signature_way == SignatureWay::Normal {
            self.signature.extend_from_slice(sign_1);
            self.signature.extend_from_slice(sign_2);
        } else {
            self.signature.extend_from_slice(sign_2);
            self.signature.extend_from_slice(sign_1);
        }
    }

    pub fn remove(&mut self, bytes: usize) {
        for _ in 0..bytes {
            self.signature.pop();
        }
    }

    /*pub fn create_hash_from_signature(&mut self) {
        self.signature_hash = xxhash_rust::xxh3::xxh3_64(&self.signature);
    }*/

    pub fn get_signature(&self) -> &[u8] {
        &self.signature
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature::new()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature
    }
}

impl Eq for Signature {}

impl Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.signature.hash(state);
    }
}

impl Clone for Signature {
    fn clone(&self) -> Self {
        Self {
            signature_way: self.signature_way,
            signature: self.signature.clone(),
            protocol_path: self.protocol_path.clone(),
        }
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\n[Signature]\n\tprotocol path:             {}\n\tsignature hash:   ",
            self.protocol_path
        )?;

        for item in &self.signature {
            write!(f, "{}", item)?;
        }

        Ok(())
    }
}
