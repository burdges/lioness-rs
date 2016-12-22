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
pub mod util;
pub use util::{xor, xor_assign};

pub const DIGEST_RESULT_SIZE: usize = 32;
pub const DIGEST_KEY_SIZE: usize = 64;
pub const STREAM_CIPHER_KEY_SIZE: usize = 32;
pub const RAW_KEY_SIZE: usize = 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE;

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
    _k1: [u8; STREAM_CIPHER_KEY_SIZE],
    _k2: [u8; DIGEST_KEY_SIZE],
    _k3: [u8; STREAM_CIPHER_KEY_SIZE],
    _k4: [u8; DIGEST_KEY_SIZE],
    // I dislike these as H and SC should not impact variance.
    h: std::marker::PhantomData<H>,
    sc: std::marker::PhantomData<SC>,
}

impl<H,SC> Lioness<H,SC>
  where H: DigestLioness+Digest,
        SC: StreamCipherLioness+SynchronousStreamCipher
{
    pub fn encrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr = [0u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        assert!(keylen == 32);

        let blocklen = block.len();
	if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let blocky = block.split_at_mut(keylen);
        let left: &mut [u8] = blocky.0; 
        let right: &mut [u8] = blocky.1;

        // rust-crypto cannot xor a stream cipher in place sadly.
        let mut tmp_right = Vec::with_capacity(blocklen-keylen);
        for _ in 0..blocklen-keylen { tmp_right.push(0u8); }
        // unsafe { tmp_right.set_len(blocklen-keylen); }
        debug_assert_eq!(tmp_right.len(),right.len());

        // R = R ^ S(L ^ K1)
        xor(left, &self._k1, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, &mut tmp_right); // .as_mut_slice()

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self._k2);
        h.input(&tmp_right);  // .as_slice()
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self._k3, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(&tmp_right, right);  // .as_slice()

        // L = L ^ H(K4, R)
        let mut h = H::new_digestlioness(&self._k4);
        h.input(&right);  // .as_slice()
        h.result(&mut hr);
        xor_assign(left,&hr);

        Ok(())
    }

    pub fn decrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr = [0u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        assert!(keylen == 32);

        let blocklen = block.len();
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
        let mut h = H::new_digestlioness(&self._k4);
        h.input(&right);  // .as_slice()
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self._k3, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, &mut tmp_right);  // .as_slice()

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self._k2);
        h.input(&tmp_right);  // .as_slice()
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K1)
        xor(left, &self._k1, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(&tmp_right, right);  // .as_mut_slice()

        Ok(())
    }

    pub fn new_raw(key: &[u8; 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE]) -> Lioness<H,SC> {
        let (k1,k2,k3,k4) = array_refs![key,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE];
        Lioness {
            _k1: *k1,
            _k2: *k2,
            _k3: *k3,
            _k4: *k4,
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
    use crypto::blake2b::Blake2b;
    use crypto::chacha20::ChaCha20;
    use self::rand::Rng;
    use self::rand::os::OsRng;

    #[test]
    fn simple_encrypt_decrypt_test() {
        const TEST_PLAINTEXT: &'static [u8] = b"Hello there world, I'm just a test string";
        let mut rnd = OsRng::new().unwrap();
        let key = rnd.gen_iter::<u8>().take(RAW_KEY_SIZE).collect::<Vec<u8>>();
        let l = Lioness::<Blake2b,ChaCha20>::new_raw(array_ref!(key,0,RAW_KEY_SIZE));
        //let l = LionessDefault::new_raw(array_ref!(key,0,RAW_KEY_SIZE));
        let mut v: Vec<u8> = TEST_PLAINTEXT.to_owned();
        assert_eq!(v,TEST_PLAINTEXT);
        l.encrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        assert_ne!(v,TEST_PLAINTEXT);
        l.decrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        assert_eq!(v[0..32],TEST_PLAINTEXT[0..32]);
        assert_eq!(v[32..],TEST_PLAINTEXT[32..]);
    }

} // tests
