// Copyright 2016 Jeffrey Burdges and David Stainton

//! Error reporting for Lioness wide block cipher.

use std::error::Error;
use std::fmt;


#[derive(Debug)]
pub enum LionessError {
    BlockSizeError,
}

impl fmt::Display for LionessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::LionessError::*;
        match *self {
            BlockSizeError => write!(f, "Lioness block size must exceed 32 bytes."),
        }
    }
}

impl From<keystream::Error> for LionessError {
    fn from(_: keystream::Error) -> LionessError {
        LionessError::BlockSizeError // EndReached is a block size error
    }
}

impl Error for LionessError {
    fn description(&self) -> &str {
        "I'm a Lioness error."
    }

    fn cause(&self) -> Option<&dyn Error> {
        use self::LionessError::*;
        match *self {
            BlockSizeError => None,
        }
    }
}



