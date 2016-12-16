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


pub const DigestResultSize: usize = 32;
pub const DigestKeySize: usize = 64;

/// Adapt a given `crypto::digest::Digest` to Lioness.
pub trait DigestLioness: Digest {
    fn new_digestlioness(k: &[u8]) -> Self;
}

impl DigestLioness for Blake2b {
    fn new_digestlioness(k: &[u8]) -> Self {
        Blake2b::new_keyed(DigestResultSize,k)
    }
}

/*
impl DigestLioness for Sha3 {
    const ResultSize: usize = 32;
    const KeySize: usize = 64;
    // Sha3::sha3_256
}
*/

const StreamCipherKeySize: usize = 32;

/// Add associated type missing from rust-crypto lacks's trait
/// `crypto::symmetriccipher::SynchronousStreamCipher`
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
    k1: [u8; StreamCipherKeySize],
    k2: [u8; DigestKeySize],
    k3: [u8; StreamCipherKeySize],
    k4: [u8; DigestKeySize],
    // I dislike these as H and SC should not impact variance.
    h: std::marker::PhantomData<H>,
    sc: std::marker::PhantomData<SC>,
}

impl<H,SC> Lioness<H,SC>
  where H: DigestLioness+Digest,
        SC: StreamCipherLioness+SynchronousStreamCipher
{
    fn encrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DigestResultSize == StreamCipherKeySize);
        let mut hr = [0u8; DigestResultSize];
        let mut k = [0u8; StreamCipherKeySize];
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
        debug_assert!(DigestResultSize == StreamCipherKeySize);
        let mut hr = [0u8; DigestResultSize];
        let mut k = [0u8; StreamCipherKeySize];
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
