// Copyright 2016 Jeffrey Burdges and David Stainton

//! Lioness wide block cipher

#[macro_use]
extern crate arrayref;
extern crate crypto;

use crypto::digest::Digest;
use crypto::blake2b::Blake2b;
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
        let left: &mut [u8] = blocky.0; 
        let right: &mut [u8] = blocky.1;

        // rust-crypto cannot xor a stream cipher in place sadly.
        let mut tmp_right = Vec::with_capacity(blocklen-keylen);
        for _ in (0..blocklen-keylen) { tmp_right.push(0u8); }
        // unsafe { tmp_right.set_len(blocklen-keylen); }
        debug_assert_eq!(tmp_right.len(),right.len());

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, &mut tmp_right); // .as_mut_slice()

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self.k2);
        h.input(&tmp_right);  // .as_slice()
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(&tmp_right, right);  // .as_slice()

        // L = L ^ H(K4, R)
        let mut h = H::new_digestlioness(&self.k4);
        h.input(&right);  // .as_slice()
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
        let left: &mut [u8] = blocky.0; 
        let right: &mut [u8] = blocky.1;

        // rust-crypto cannot xor a stream cipher in place sadly.
        let mut tmp_right = Vec::with_capacity(blocklen-keylen);
        // for _ in (0..blocklen-keylen) { tmp.push(0u8); }
        unsafe { tmp_right.set_len(blocklen-keylen); }

        // L = L ^ H(K4, R)
        let mut h = H::new_digestlioness(&self.k4);
        h.input(&right);  // .as_slice()
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, &mut tmp_right);  // .as_slice()

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self.k2);
        h.input(&tmp_right);  // .as_slice()
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(&tmp_right, right);  // .as_mut_slice()

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

// pub type LionessDefault = Lioness<Blake2b,ChaCha20>;


#[cfg(test)]
mod tests {
use super::*;

extern crate rand;
use self::rand::Rng;
use self::rand::os::OsRng;

const test_plaintext: &'static [u8] = b"Hello there world, I'm just a test string";

const RAW_KEY_SIZE: usize = 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE;
type RawKey = [u8; RAW_KEY_SIZE];
// const ZeroRawKey: &'static [u8] = &[0u8; RawKeySize];

#[test]
fn it_works() {
    let mut rnd = OsRng::new().unwrap();
    let key = rnd.gen_iter::<u8>().take(RAW_KEY_SIZE).collect::<Vec<u8>>();
    let l = Lioness::<Blake2b,ChaCha20>::new_raw(array_ref!(key,0,RAW_KEY_SIZE));
    let mut v: Vec<u8> = test_plaintext.to_owned();
    assert_eq!(v,test_plaintext);
    l.encrypt(&mut v).unwrap();  // .as_mut_slice()
    assert_eq!(v.len(),test_plaintext.len());
    // assert_ne!(v,test_plaintext);
    // assert!( v.iter.zip(test_plaintext.iter()).all(|(x,y)| x!=y) );
    l.decrypt(&mut v).unwrap();  // .as_mut_slice()
    assert_eq!(v.len(),test_plaintext.len());
    assert_eq!(v[0..32],test_plaintext[0..32]);
    assert_eq!(v[32..],test_plaintext[32..]);
}

} // mod tests

