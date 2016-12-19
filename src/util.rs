
/// Simple slice xor function modified from:
/// https://github.com/DaGenix/rust-crypto/blob/master/src/scrypt.rs
pub fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    assert!( x.len() == y.len() && x.len() == output.len() );
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}

pub fn xor_assign(a: &mut [u8], b: &[u8]) {
    assert!( a.len() == b.len() );
    for (a_i, &b_i) in a.iter_mut().zip(b.iter()) {
        *a_i ^= b_i;
    }
}
