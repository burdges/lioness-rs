// Copyright 2016 Jeffrey Burdges and David Stainton

//! Lioness wide block cipher
#[macro_use]
extern crate arrayref;

extern crate chacha;
extern crate blake2;
extern crate digest;
extern crate keystream;
extern crate blake3;

#[cfg(test)]
extern crate rand;
#[cfg(test)]
extern crate hex;


use keystream::KeyStream;
use chacha::ChaCha;
use blake2::Blake2bMac;
use blake3::Hasher;
use digest::{KeyInit, Update, FixedOutput, consts::U32};
use std::{io::Read, convert::TryInto};

pub mod error;
pub use error::LionessError;
pub mod util;
pub use util::{xor, xor_assign};

pub const DIGEST_RESULT_SIZE: usize = 32;
pub const DIGEST_KEY_SIZE: usize = 64;
pub const BLAKE3_RESULT_SIZE: usize = 32;
pub const BLAKE3_KEY_SIZE: usize = 32;
pub const STREAM_CIPHER_KEY_SIZE: usize = 32;
pub const RAW_KEY_SIZE: usize = 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE;
pub const RAW_BLAKE3_KEY_SIZE: usize = 2*STREAM_CIPHER_KEY_SIZE + 2*BLAKE3_KEY_SIZE;
const CHACHA20_NONCE_SIZE: usize = 8;

// Type alias for Blake2bMac256 for compatibility with old lioness
pub type Blake2bMac256 = Blake2bMac<U32>;
pub type Blake3Hasher = Hasher;

/// Adapt a given `crypto::digest::Digest` to Lioness.
pub trait DigestLioness : KeyInit+Update+FixedOutput {
	
    fn new_digest_lioness(key: &[u8]) -> Self;
	
}

pub trait Blake3 {
	
    fn new_blake3(key: &[u8; BLAKE3_KEY_SIZE]) -> Blake3Hasher;
	
}

impl DigestLioness for Blake2bMac256 {
	
    fn new_digest_lioness(key: &[u8]) -> Blake2bMac256 {
        Blake2bMac256::new_from_slice(&key).unwrap()
    }
	
}

impl Blake3 for Blake3Hasher {
	
    fn new_blake3(key: &[u8; BLAKE3_KEY_SIZE]) -> Blake3Hasher {
        Blake3Hasher::new_keyed(key)
    }
	
}

pub trait StreamCipherLioness : KeyStream {
	
    fn new_streamcipher_lioness(k: &[u8; STREAM_CIPHER_KEY_SIZE]) -> Self;
	
}

impl StreamCipherLioness for ChaCha {
	
    fn new_streamcipher_lioness(k: &[u8; STREAM_CIPHER_KEY_SIZE]) -> ChaCha {
        ChaCha::new_chacha20(k, &[0u8;CHACHA20_NONCE_SIZE])
    }
	
}

pub struct Lioness<H,SC>
where 
	H: DigestLioness+KeyInit+Update+FixedOutput, 
    SC: StreamCipherLioness+KeyStream {
		k1: [u8; STREAM_CIPHER_KEY_SIZE],
		k2: [u8; DIGEST_KEY_SIZE],
		k3: [u8; STREAM_CIPHER_KEY_SIZE],
		k4: [u8; DIGEST_KEY_SIZE],
		h: std::marker::PhantomData<H>,
		sc: std::marker::PhantomData<SC>,
	}

pub struct LionessBlake3<H,SC>
where
	H: Blake3,
	SC: StreamCipherLioness+KeyStream {
		k1: [u8; STREAM_CIPHER_KEY_SIZE],
		k2: [u8; BLAKE3_KEY_SIZE],
		k3: [u8; STREAM_CIPHER_KEY_SIZE],
		k4: [u8; BLAKE3_KEY_SIZE],
		h: std::marker::PhantomData<H>,
		sc: std::marker::PhantomData<SC>,
	}

impl<H,SC> Lioness<H,SC>
where 
	H: DigestLioness+KeyInit+Update+FixedOutput,
    SC: StreamCipherLioness+KeyStream
{
    pub fn encrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr : [u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        debug_assert!(keylen == 32);

        let blocklen = block.len();
        if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let (left,right) : (&mut [u8],&mut [u8]) = block.split_at_mut(keylen);

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k);
        sc.xor_read(right) ?;

        // L = L ^ H(K2, R)
        let mut h = H::new_digest_lioness(&self.k2);
        h.update(&mut *right);
        hr = h.finalize_fixed().as_slice().try_into().expect("slice with incorrect length");
		xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k);
        sc.xor_read(right) ?;

        // L = L ^ H(K4, R)
        let mut h = H::new_digest_lioness(&self.k4);
        h.update(&mut *right);
        hr = h.finalize_fixed().as_slice().try_into().expect("slice with incorrect length");
		xor_assign(left,&hr);

        Ok(())
    }

    pub fn decrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr : [u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        debug_assert!(keylen == 32);

        let blocklen = block.len();
	    if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let (left,right) : (&mut [u8],&mut [u8]) = block.split_at_mut(keylen);

        // L = L ^ H(K4, R)
        let mut h = H::new_digest_lioness(&self.k4);
        h.update(&mut *right);
        hr = h.finalize_fixed().as_slice().try_into().expect("slice with incorrect length");
		xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k);
        sc.xor_read(right) ?;

        // L = L ^ H(K2, R)
        let mut h = H::new_digest_lioness(&self.k2);
        h.update(&mut *right);
		hr = h.finalize_fixed().as_slice().try_into().expect("slice with incorrect length");
		xor_assign(left,&hr);

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k);
        sc.xor_read(right) ?;

        Ok(())
    }

    /// Given a key, create a new Lioness cipher
    pub fn new_raw(key: &[u8; 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE]) -> Lioness<H,SC> {
        let (_k1,_k2,_k3,_k4) = array_refs![key,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE];
        Lioness {
            k1: *_k1,
            k2: *_k2,
            k3: *_k3,
            k4: *_k4,
            h: std::marker::PhantomData,
            sc: std::marker::PhantomData,
        }
    }
}

impl<H,SC> LionessBlake3<H,SC>
where
	H: Blake3,
	SC: StreamCipherLioness+KeyStream
{
    pub fn encrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(BLAKE3_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr = [0u8; BLAKE3_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        debug_assert!(keylen == 32);

        let blocklen = block.len();
        if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let (left,right) : (&mut [u8],&mut [u8]) = block.split_at_mut(keylen);

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k);
        sc.xor_read(right) ?;

        // L = L ^ H(K2, R)
        let mut h = H::new_blake3(&self.k2);
        h.update(&mut *right);
        h.finalize_xof().read(&mut hr).unwrap();
		xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k);
        sc.xor_read(right) ?;

        // L = L ^ H(K4, R)
        let mut h = H::new_blake3(&self.k4);
        h.update(&mut *right);
        h.finalize_xof().read(&mut hr).unwrap();
		xor_assign(left,&hr);

        Ok(())
    }

    pub fn decrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(BLAKE3_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr = [0u8; BLAKE3_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        debug_assert!(keylen == 32);

        let blocklen = block.len();
	    if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let (left,right) : (&mut [u8],&mut [u8]) = block.split_at_mut(keylen);

        // L = L ^ H(K4, R)
        let mut h = H::new_blake3(&self.k4);
        h.update(&mut *right);
        h.finalize_xof().read(&mut hr).unwrap();
		xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k);
        sc.xor_read(right) ?;

        // L = L ^ H(K2, R)
        let mut h = H::new_blake3(&self.k2);
        h.update(&mut *right);
		h.finalize_xof().read(&mut hr).unwrap();
		xor_assign(left,&hr);

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k);
        sc.xor_read(right) ?;

        Ok(())
    }

    /// Given a key, create a new Lioness cipher
    pub fn new_raw(key: &[u8; 2*STREAM_CIPHER_KEY_SIZE + 2*BLAKE3_KEY_SIZE]) -> LionessBlake3<H,SC> {
        let (_k1,_k2,_k3,_k4) = array_refs![key,STREAM_CIPHER_KEY_SIZE,BLAKE3_KEY_SIZE,STREAM_CIPHER_KEY_SIZE,BLAKE3_KEY_SIZE];
        LionessBlake3 {
            k1: *_k1,
            k2: *_k2,
            k3: *_k3,
            k4: *_k4,
            h: std::marker::PhantomData,
            sc: std::marker::PhantomData,
        }
    }
}

pub type LionessDefault = Lioness<Blake2bMac256,ChaCha>;

#[cfg(test)]
mod tests {
    use rand::prelude::*;
	use digest::generic_array::GenericArray;
    use super::*;

    struct Test {
        input: Vec<u8>,
        output: Vec<u8>,
        key: Vec<u8>,
    }

    #[test]
    fn simple_encrypt_decrypt_test() {
        const TEST_PLAINTEXT: &'static [u8] = b"Hello there world, I'm just a test string";
        let mut key = [0u8; RAW_KEY_SIZE];
        thread_rng().fill_bytes(&mut key);
        let l = Lioness::<Blake2bMac256,ChaCha>::new_raw(&key);
        let mut v: Vec<u8> = TEST_PLAINTEXT.to_owned();
        assert_eq!(v,TEST_PLAINTEXT);
        l.encrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        l.decrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
        l.decrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        l.encrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
    }
	
	#[test]
    fn simple_encrypt_decrypt_blake3_test() {
        const TEST_PLAINTEXT: &'static [u8] = b"Hello there world, I'm just a test string";
        let mut key = [0u8; RAW_BLAKE3_KEY_SIZE];
        thread_rng().fill_bytes(&mut key);
        let l = LionessBlake3::<Blake3Hasher,ChaCha>::new_raw(&key);
        let mut v: Vec<u8> = TEST_PLAINTEXT.to_owned();
        assert_eq!(v,TEST_PLAINTEXT);
        l.encrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        l.decrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
        l.decrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        l.encrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
    }

    fn test_cipher(tests: &[Test]) {
        for t in tests {
            let cipher = Lioness::<Blake2bMac256,ChaCha>::new_raw(array_ref!(t.key.as_slice(), 0, RAW_KEY_SIZE));
            let mut block: Vec<u8> = t.input.as_slice().to_owned();
            cipher.encrypt(&mut block).unwrap();
            let want: Vec<u8> = t.output.as_slice().to_owned();
            assert_eq!(want, block)
        }
    }
	
    #[test]
    fn chach20_blake2b_lioness_vectors_test() {
        let key = hex::decode(
            "0f2c69732932c99e56fa50fbb2763ad77ee221fc5d9e6c08f89fc577a7467f1ee34003440ee2bfbf\
             aac60912b0e547fbe9a6a9292db70bc718c6f2773ab198ac8f255378f7ea799e1d4b8596079173b6\
             e443c416f13195f1976acc03d53a4b8581b609df3b7029d5b487051d5ae4189129c045edc8822e1f\
             52e30251e4b322b3f6d6e8bb0ddb0578dcba41603abf5e51848c84d2082d293f30a645faf4df028e\
             e2c40853ea33e40b55fca902371dc00dc1e0e77161bd097a59e8368bf99174d9").unwrap();
        let input = hex::decode(
            "5ac4cb9674a8908915a2b1aaf2043271612531911a26186bd5c811951330753a0e3259f3fcf52f\
             b86e666ab4d96243e57d73b976611f928d44ad137799016861576ca0a6b8a8a9e2ea02db71e71c\
             9654e476ca845c44456eba62f11f004b222756e485185c446c30b7a05cf9acd53b3131227b428d\
             a5c9601664d45ae5c2387956307961a0680894844190605dce0c86e597105884e151eb8a005eda\
             08ff5891a6b40bae299cddad979063a9a356f3477feabb9cc7bd80a1e2d6a419fcd8af9e98f7b1\
             93c71bd6056d7634b8c2b8f85920f314554104659e52d9266ddbc2ac40c1b875f6b00225f832cf\
             310e139ad8cc2568608f0323534fa15a84280e776e7e1167a001f6e18c49f3cd02c19837da47ac\
             091219ee2fdb4458836db20cbd362bb65add9b40f2817f666caf19787abc2013737eea8c7552d7\
             55a29beba5da31956f75fe7628221fe8d0a75da5bee39af956a2246c5a339560dcf029eb76d191\
             963354b70142df29ec69930977ce2f0e491513664ce83a8fa75f3e698530cf9dafbdb90b19745e\
             9257d03d7320c6d306f529eda242cb3f6f452a943f6e1c04eb02cbb0368d79e49a2b42ac3ff7cd\
             9a5686bfdb90a29322016bbcef5c733f451a9f4ea7c534116158eb611796d47b83ffe7cd6e6c11\
             d56e2d26c7a386853212a2f92efeabc74e8fe69e3d374d7b033d0ec9862221435b14ad534217ad\
             7da50bc236").unwrap();
        let output = hex::decode(
            "9eb45ca2ca4d0b6ff05a749511aad1357aa64caf9ce547c7388fe24fd1300fe856bb5c396869a\
             cd21c45805e6a7c8a1b7f71cc5f0ea9dd0c4ecd4bba9a7a4853bc352bc9f6562e9907973f91fb\
             cf7c710f5a89abc8eb4489b90e8111cbf85ffd595d603268ddceb40e39e747a4e7bd5c965585b\
             6964e180bd6ccb9d0fad210c7f7dd6f90cf6db9bda70d41d3922cedec5ea147ef318de5f34e6f\
             e5bd646859a9d4171b973b6b58c8d7f94bc9eb293c197f3408a51e3626196e3f6bca625cef90f\
             a7a3e3713bdaebdda82f48db1a97c9ed5c48bc419dbc3d1f9ef43d1b17dd83c966bde9d9360b7\
             cdac0871844c27921dcf3bb7edce9fb24661a41a8f92c8502925f062e9cd2f77c561e5825eae2\
             11657652330bc64cd63b18d1014975f167f8b68d6e702dd3d3547971662238216cc5b07517cc9\
             0aaa49a61ee423861cdc49c0e1f64e086007095a00f8adb0314fd85c88158001202edf2ed43c2\
             01176d6141e469dd89430352a927ee22a41c62c8cfdfd5d592e76793e58a9c63b7fe6dad335d7\
             acec90727675854d7708358115794e013bb4fdb504c44e21ce500f764fac211e8de20b81ca55f\
             c778ace024d2a40045241e71b023ceb519c8c28285c333b9f90f5e2cde21ca6744e43f89d0054\
             5dd34df072c7214f6cbd2123c4b0613614609961dd855d6d611c3018e4df3550b4e93f33f7c3e\
             8b2c890ca0405c957aa277d").unwrap();

        test_cipher(&[ Test {key,input,output} ]);
    }
	
	#[test]
    fn encryption_is_reciprocal_to_decryption_for_chacha20_blake3_variant() {
        let key = GenericArray::from(b"my-awesome-key-that-is-perfect-length-to-work-with-chacha20-and-blake3-lioness-cipher-after-adding-a-little-bit-of-extra-padding".to_owned()).as_slice().try_into().expect("slice with incorrect length");
		let l = LionessBlake3::<Blake3Hasher,ChaCha>::new_raw(&key);
        let data = b"Hello there! This is some test data that has length at least as long as the digest size of Blake3.";
        let mut block = *data;
		l.encrypt(&mut block).unwrap();
		assert_ne!(data.to_vec(), block.to_vec());
		l.decrypt(&mut block).unwrap();
		assert_eq!(data.to_vec(), block.to_vec());
    }
	
	#[test]
    fn encryption_is_reciprocal_to_decryption_for_block_chacha20_blake3_variant() {
        let key = GenericArray::from(b"my-awesome-key-that-is-perfect-length-to-work-with-chacha20-and-blake3-lioness-cipher-after-adding-a-little-bit-of-extra-padding".to_owned()).as_slice().try_into().expect("slice with incorrect length");
		let l = LionessBlake3::<Blake3Hasher,ChaCha>::new_raw(&key);
        let data = b"This is some test data of the same length as specified blockSize".to_owned();
        let mut block = GenericArray::from(data);
		l.encrypt(&mut block).unwrap();
        assert_ne!(data.to_vec(), block.to_vec());
		l.decrypt(&mut block).unwrap();
        assert_eq!(data.to_vec(), block.to_vec());
    }
} // tests
