
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_xor_test() {
        let x = [0x8e, 0xc6, 0xcb, 0x71];
        let y = [0x2e, 0x51, 0xa9, 0x21];
        let mut output = [1u8; 4];
        xor(&x, &y, &mut output);
        let want = hex::decode("a0976250").unwrap();
        assert_eq!(output, want.as_slice());
    }

    #[test]
    fn simple_xor_assign_test() {
        let mut x = [0x8e, 0xc6, 0xcb, 0x71];
        let y = [0x2e, 0x51, 0xa9, 0x21];
        xor_assign(&mut x, &y);
        let want = hex::decode("a0976250").unwrap();
        assert_eq!(x, want.as_slice());
    }
}
