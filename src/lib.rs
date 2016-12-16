// Copyright 2016 Jeffrey Burdges and David Stainton

//! Lioness wide block cipher


#![feature(associated_consts)]

extern crate crypto;

#[macro_use]
extern crate arrayref;

pub mod error;
pub use error::LionessError;

use crypto::digest::Digest;
use crypto::blake2b::Blake2b;
use crypto::sha3::Sha3;

use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;


/// Simple slice xor function modified from:
/// https://github.com/DaGenix/rust-crypto/blob/master/src/scrypt.rs
fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    assert!( x.len() == y.len() && x.len() == output.len() );
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}

fn xor_assign(a: &mut [u8], b: &[u8]) {
    assert!( a.len() == b.len() );
    for (a_i, &b_i) in a.iter_mut().zip(b.iter()) {
        *a_i ^= b_i;
    }
}


/*
pub trait LionessCipher {
    type DigestT;
    type StreamCipherT;
}
*/


/// Add associated type missing from `crypto::digest::Digest`
/// in rust-crypto.
pub trait DigestLioness: Digest {
    const ResultSize: usize;
    const KeySize: usize;

    fn new_digestlioness(k: &[u8; KeySize]) -> Self;
}

impl DigestLioness for Blake2b {
    const ResultSize: usize = 64;
    const KeySize: usize = 64;
    fn new_digestlioness(k: &[u8; KeySize]) -> Self {
        Blake2b::new_keyed(64,k)
    }
}

/*
impl DigestLioness for Sha3 {
    const ResultSize: usize = 32;
    const KeySize: usize = 64;
    // Sha3::sha3_256
}
*/


/// Add associated type missing from rust-crypto lacks's trait
/// `crypto::symmetriccipher::SynchronousStreamCipher`
pub trait StreamCipherLioness: SynchronousStreamCipher {
    const KeySize: usize;
    fn new_streamcipherlioness(k: &[u8; KeySize]) -> Self;
}

impl StreamCipherLioness for ChaCha20 {
    const KeySize: usize = 64;
    fn new_streamcipherlioness(k: &[u8; KeySize]) -> ChaCha20 {
        ChaCha20::new(k, &[0u8;12])
    }
}

// H::Key = <H as DigestLioness>::Key
// SC::Key = <SC as StreamCipherLioness>::Key


/// Lioness implemented generically over a Digest and StreamCipher
pub struct Lioness<H,SC>
  where H: DigestLioness+Digest, 
        SC: StreamCipherLioness+SynchronousStreamCipher {
    k1: [u8; <SC as StreamCipherLioness>::KeySize],
    k2: [u8; <H as DigestLioness>::KeySize],
    k3: [u8; <SC as StreamCipherLioness>::KeySize],
    k4: [u8; <H as DigestLioness>::KeySize],
}

impl<H,SC> Lioness<H,SC>
  where H: DigestLioness+Digest,
        SC: StreamCipherLioness+SynchronousStreamCipher
{
    fn encrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        let mut hr: [u8; <H as DigestLioness>::ResultSize];
        let mut k: <SC as StreamCipherLioness>::Key;
        let keylen = std::mem::size_of_val(k);

        let blocklen = block.len();
        // assert!(len > keylen);
	if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let mut left; let mut right;
        (left,right) = block.split_at_mut(keylen);

        // rust-crypto cannot xor a stream cipher in place sadly.
        let mut tmp_right = Vec::with_capacity(blocklen-keylen);
        // for _ in (0..blocklen-keylen) { tmp.push(0u8); }
        unsafe { tmp_right.set_len(blocklen-keylen); }

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, tmp_right.as_mut_slice());

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self.k2);
        h.input(tmp_right.as_slice());
        h.result(&hr);
        xor_assign(left,&hr[0..keylen]);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(tmp_right.as_slice(), right);

        // L = L ^ H(K4, R)
        let mut h = H::new_digestlioness(&self.k2);
        h.input(tmp_right.as_slice());
        h.result(&hr);
        xor_assign(left,&hr[0..keylen]);

        Ok(())
    }

    fn decrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {

// ...

        Ok(())
    }

/*
    pub fn new_(key: &[u8; 32]) -> Lioness<H,S> {
        Ok(Lioness<H,S> {
        })
    }
*/
}



 

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
