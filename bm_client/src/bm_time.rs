use time::{Timespec,get_time};

pub trait TimeGenerator {
    fn get_time(&self) -> Timespec;
}

pub type TimeFn = Box<TimeGenerator>;

pub struct StdTimeGenerator;

impl StdTimeGenerator {
    pub fn new() -> StdTimeGenerator {
        StdTimeGenerator
    }
}

impl TimeGenerator for StdTimeGenerator {
    fn get_time(&self) -> Timespec {
        get_time()
    }
}

#[cfg(test)]
pub struct StaticTimeGenerator {
    time: Timespec
}

#[cfg(test)]
impl StaticTimeGenerator {
    pub fn new(time: Timespec) -> StaticTimeGenerator {
        StaticTimeGenerator {
            time: time
        }
    }
}

#[cfg(test)]
impl TimeGenerator for StaticTimeGenerator {
    fn get_time(&self) -> Timespec {
        self.time
    }
}
