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
const CHACHA20_NONCE_SIZE: usize = 8;

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
        ChaCha20::new(k, &[0u8;CHACHA20_NONCE_SIZE])
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
    h: std::marker::PhantomData<H>,
    sc: std::marker::PhantomData<SC>,
}

impl<H,SC> Lioness<H,SC>
  where H: DigestLioness+Digest,
        SC: StreamCipherLioness+SynchronousStreamCipher
{
    /// encrypt a block
    ///
    /// # Arguments
    ///
    /// * `block` - a mutable byte slice of data to encrypt
    ///
    /// # Errors
    ///
    /// * `LionessError::BlockSizeError` - returned if block size is too small
    ///
    /// # Example
    ///
    /// ```
    /// extern crate crypto;
    /// extern crate lioness;
    /// extern crate rustc_serialize;
    /// use self::rustc_serialize::hex::FromHex;
    /// use self::lioness::{Lioness, RAW_KEY_SIZE};
    /// use crypto::chacha20::ChaCha20;
    /// use crypto::blake2b::Blake2b;
    /// # #[macro_use] extern crate arrayref; fn main() {
    ///
    /// let key = "e98e0e3f28311995e8448e6dc1de73159e800c8184a7846418347f4490f063e372\
    /// 6eebda84e02f2cc218bd6c6e9a9b801e8d8899e8f5b6dcd23bf7ca7f11641c584cd9568f045e9\
    /// ad92c59275f67b9bed7f02bb23e28c0b8e56fbb634d60a6d1eae7145e53a4442dda40ae37b2e2\
    /// e1f97ae495c8ce0166605d4f1ea91f139159229f208c69362095d8d8e00d7b4c9ca5603dc8b87\
    /// 50b0eb500670858ca7983a8760be307ff3e5c05f22799cb60d7c57fe3fc8b980aa65e89e3ac0a\
    /// c147af7deb".from_hex().unwrap();
    ///
    /// const PLAINTEXT: &'static [u8] = b"Open, secure and reliable
    /// connectivity is necessary (although not sufficient) to
    /// excercise the human rights such as freedom of expression and
    /// freedom of association [FOC], as defined in the Universal
    /// Declaration of Human Rights [UDHR]. The purpose of the
    /// Internet to be a global network of networks that provides
    /// unfettered connectivity to all users and for any content
    /// [RFC1958]. This objective of stimulating global connectivity
    /// contributes to the Internet's role as an enabler of human
    /// rights.";
    ///
    /// let mut block: Vec<u8> = PLAINTEXT.to_owned();
    /// let cipher = Lioness::<Blake2b,ChaCha20>::new_raw(array_ref!(key, 0, RAW_KEY_SIZE));
    /// cipher.encrypt(&mut block).unwrap();
    /// }
    /// ```
    pub fn encrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr = [0u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        debug_assert!(keylen == 32);

        let blocklen = block.len();
	if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let blocky = block.split_at_mut(keylen);
        let left: &mut [u8] = blocky.0; 
        let right: &mut [u8] = blocky.1;

        let mut tmp_right = Vec::with_capacity(blocklen-keylen);
        for _ in 0..blocklen-keylen { tmp_right.push(0u8); }
        debug_assert_eq!(tmp_right.len(),right.len());

        // R = R ^ S(L ^ K1)
        xor(left, &self._k1, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, &mut tmp_right);

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self._k2);
        h.input(&tmp_right);
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self._k3, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(&tmp_right, right);

        // L = L ^ H(K4, R)
        let mut h = H::new_digestlioness(&self._k4);
        h.input(&right);
        h.result(&mut hr);
        xor_assign(left,&hr);

        Ok(())
    }

    /// decrypt a block
    ///
    /// # Arguments
    ///
    /// * `block` - a mutable byte slice of data to decrypt
    ///
    /// # Errors
    ///
    /// * `LionessError::BlockSizeError` - returned if block size is too small
    ///
    pub fn decrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        let mut hr = [0u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        debug_assert!(keylen == 32);

        let blocklen = block.len();
	if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let blocky = block.split_at_mut(keylen);
        let left: &mut [u8] = blocky.0; 
        let right: &mut [u8] = blocky.1;

        let mut tmp_right = Vec::with_capacity(blocklen-keylen);
        for _ in 0..blocklen-keylen { tmp_right.push(0u8); }

        // L = L ^ H(K4, R)
        let mut h = H::new_digestlioness(&self._k4);
        h.input(&right);
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K3)
        xor(left, &self._k3, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(right, &mut tmp_right);

        // L = L ^ H(K2, R)
        let mut h = H::new_digestlioness(&self._k2);
        h.input(&tmp_right);
        h.result(&mut hr);
        xor_assign(left,&hr);

        // R = R ^ S(L ^ K1)
        xor(left, &self._k1, &mut k);
        let mut sc = SC::new_streamcipherlioness(&k);
        sc.process(&tmp_right, right);

        Ok(())
    }

    /// Given a key, create a new Lioness cipher
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

pub type LionessDefault = Lioness<Blake2b,ChaCha20>;


#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;
    use super::*;
    use crypto::blake2b::Blake2b;
    use crypto::chacha20::ChaCha20;
    use self::rand::Rng;
    use self::rand::os::OsRng;
    use self::rustc_serialize::hex::FromHex;

    struct Test {
        input: Vec<u8>,
        output: Vec<u8>,
        key: Vec<u8>,
    }

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
        l.decrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
        l.decrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        l.encrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
    }

    fn test_cipher(tests: &[Test]) {
        for t in tests {
            let cipher = Lioness::<Blake2b,ChaCha20>::new_raw(array_ref!(t.key.as_slice(), 0, RAW_KEY_SIZE));
            let mut block: Vec<u8> = t.input.as_slice().to_owned();
            cipher.encrypt(&mut block).unwrap();
            let want: Vec<u8> = t.output.as_slice().to_owned();
            assert_eq!(want, block)
        }
    }

    #[test]
    fn chach20_blake2b_lioness_vectors_test() {
        let test_vectors = vec![
            Test {
                key: "0f2c69732932c99e56fa50fbb2763ad77ee221fc5d9e6c08f89fc577a7467f1ee34003440ee2bfbf\
                      aac60912b0e547fbe9a6a9292db70bc718c6f2773ab198ac8f255378f7ea799e1d4b8596079173b6\
                      e443c416f13195f1976acc03d53a4b8581b609df3b7029d5b487051d5ae4189129c045edc8822e1f\
                      52e30251e4b322b3f6d6e8bb0ddb0578dcba41603abf5e51848c84d2082d293f30a645faf4df028e\
                      e2c40853ea33e40b55fca902371dc00dc1e0e77161bd097a59e8368bf99174d9".from_hex().unwrap(),
                input: "5ac4cb9674a8908915a2b1aaf2043271612531911a26186bd5c811951330753a0e3259f3fcf52f\
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
                        7da50bc236".from_hex().unwrap(),
                output: "9eb45ca2ca4d0b6ff05a749511aad1357aa64caf9ce547c7388fe24fd1300fe856bb5c396869a\
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
                         8b2c890ca0405c957aa277d".from_hex().unwrap(),
            }];

        test_cipher(&test_vectors[..]);
    }
} // tests
