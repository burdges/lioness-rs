
This crate provides the Lioness wide block cipher instantiated with ChaCha20 and Blake2b.

[![build status](https://api.travis-ci.org/burdges/lioness-rs.png)](https://travis-ci.org/burdges/lioness-rs)
[![documenation](https://docs.rs/lioness/badge.svg)](https://docs.rs/lioness/)
[![crates.io link](https://img.shields.io/crates/v/lioness.svg)](https://crates.io/crates/lioness)

### Warning

This code has not been formally audited and should only be use with extreme care and advice from competent cryptographers.  That said, Lionness' security properties mostly reduce to the underlying stream cipher and hash function.


### Details

Lioness is a wide block cipher built from a stream cipher and a hash
function.  It remains secure so long as either the stream cipher or
the hash function remains secure.  Lioness is described in
**Two Practical and Provably Secure Block Ciphers: BEAR and LION**
by *Ross Anderson* and *Eli Biham*. 
See <https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf>

We instantiate Lioness with Chacha20 and Blake2b here, but you can
easily alter these choices so long as the digest output is equal to
the stream cipher key size.

Documentation is available at <https://docs.rs/lioness/>


### Installation

This crate works with Cargo and is on
[crates.io](https://crates.io/crates/lioness).  Add it to your `Cargo.toml` with:

```toml
[dependencies]
lioness = "^0.1"
```

Use the crate like:

```rust
extern crate lioness;

...
```

### License

Lioness-rs is free software made available via the MIT License.
License details located in the LICENSE file.
