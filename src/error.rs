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
            BlockSizeError => write!(f, self.description()),
        }
    }
}


impl Error for LionessError {
    fn description(&self) -> &str {
        "I'm a Lioness error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::LionessError::*;
        match *self {
            BlockSizeError(ref err) => None,
        }
    }
}



