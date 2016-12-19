// Copyright 2016 Jeffrey Burdges and David Stainton

//! Lioness wide block cipher


// Associated constant do not work even in nightly yet.
// #![feature(associated_consts)]


#[macro_use]
extern crate arrayref;

extern crate crypto;

use crypto::digest::Digest;
use crypto::blake2b::Blake2b;
use crypto::sha3::Sha3;

use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;


pub mod error;
pub use error::LionessError;

mod util;
use util::{xor, xor_assign};


pub const DIGEST_RESULT_SIZE: usize = 32;
pub const DIGEST_KEY_SIZE: usize = 64;
const STREAM_CIPHER_KEY_SIZE: usize = 32;

/// Adapt a given `crypto::digest::Digest` to Lioness.
pub trait DigestLioness: Digest {
    fn new_digestlioness(k: &[u8]) -> Self;
}

impl DigestLioness for Blake2b {
    fn new_digestlioness(k: &[u8]) -> Self {
        Blake2b::new_keyed(DIGEST_RESULT_SIZE,k)
    }
}

/*
impl DigestLioness for Sha3 {
    const ResultSize: usize = 32;
    const KeySize: usize = 64;
    // Sha3::sha3_256
}
*/


/// Adapt a given `crypto::symmetriccipher::SynchronousStreamCipher`
/// to lioness.
pub trait StreamCipherLioness: SynchronousStreamCipher {
    fn new_streamcipherlioness(k: &[u8]) -> Self;
}

impl StreamCipherLioness for ChaCha20 {
    fn new_streamcipherlioness(k: &[u8]) -> ChaCha20 {
        ChaCha20::new(k, &[0u8;12])
    }
}


/// Lioness implemented generically over a Digest and StreamCipher
pub struct Lioness<H,SC>
  where H: DigestLioness+Digest, 
        SC: StreamCipherLioness+SynchronousStreamCipher {
    k1: [u8; STREAM_CIPHER_KEY_SIZE],
    k2: [u8; DIGEST_KEY_SIZE],
    k3: [u8; STREAM_CIPHER_KEY_SIZE],
    k4: [u8; DIGEST_KEY_SIZE],
    // I dislike these as H and SC should not impact variance.
    h: std::marker::PhantomData<H>,
    sc: std::marker::PhantomData<SC>,
}

impl<H,SC> Lioness<H,SC>
  where H: DigestLioness+Digest,
        SC: StreamCipherLioness+SynchronousStreamCipher
{
    fn encrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr = [0u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        assert!(keylen == 32);

        let blocklen = block.len();
        // assert!(len > keylen);
	if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let blocky = block.split_at_mut(keylen);
        let mut left = blocky.0; 
        let mut right = blocky.1;

        // rust-crypto cannot xor a stream cipher in place sadly.
        let mut tmp_right = Vec::with_capacity(blocklen-keylen);
        // for _ in (0..blocklen-keylen) { tmp.push(0u8); }
        unsafe { tmp_right.set_len(blocklen-keylen); }

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, tmp_right.as_mut_slice());

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self.k2);
        h.input(tmp_right.as_slice());
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(tmp_right.as_slice(), right);

        // L = L ^ H(K4, R)
        let mut h = H::new_digestlioness(&self.k4);
        h.input(tmp_right.as_slice());
        h.result(&mut hr);
        xor_assign(left,&hr);

        Ok(())
    }

    fn decrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr = [0u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        assert!(keylen == 32);

        let blocklen = block.len();
        // assert!(len > keylen);
	if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let blocky = block.split_at_mut(keylen);
        let mut left = blocky.0; 
        let mut right = blocky.1;

        // rust-crypto cannot xor a stream cipher in place sadly.
        let mut tmp_right = Vec::with_capacity(blocklen-keylen);
        // for _ in (0..blocklen-keylen) { tmp.push(0u8); }
        unsafe { tmp_right.set_len(blocklen-keylen); }

        // L = L ^ H(K4, R)
        let mut h = H::new_digestlioness(&self.k4);
        h.input(tmp_right.as_slice());
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(tmp_right.as_slice(), right);

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self.k2);
        h.input(tmp_right.as_slice());
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, tmp_right.as_mut_slice());

        Ok(())
    }

    fn new_raw(key: &[u8; 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE]) -> Lioness<H,SC> {
        let (k1,k2,k3,k4) = array_refs![key,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE];
        Lioness {
            k1: *k1, 
            k2: *k2, 
            k3: *k3, 
            k4: *k4,
            h: std::marker::PhantomData,
            sc: std::marker::PhantomData,
        }
    }
}



 

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
