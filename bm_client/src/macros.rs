#![macro_use]
macro_rules! break_on_err (
    ($expr:expr) => ({
        match $expr {
            Ok(val) => val,
            Err(_) => break
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
