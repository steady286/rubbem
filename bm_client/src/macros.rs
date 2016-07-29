#![macro_use]
macro_rules! break_on_err (
    ($expr:expr) => ({
        match $expr {
            Ok(val) => val,
            Err(_) => break
        }
    })
);

macro_rules! continue_on_err (
    ($expr:expr) => ({
        match $expr {
            Ok(val) => val,
            Err(_) => continue
        }
    })
);

macro_rules! return_on_err {
    ($expr:expr) => ({
        match $expr {
            Ok(val) => val,
            Err(_) => return
        }
    })
}

macro_rules! break_on_none (
    ($expr:expr) => ({
        match $expr {
            Some(val) => val,
            None => break
        }
    })
);
