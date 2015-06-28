use time::{Timespec,get_time};

pub trait TimeGenerator : Copy {
    fn get_time(&self) -> Timespec;
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct StandardTimeGenerator;

impl StandardTimeGenerator {
    pub fn new() -> StandardTimeGenerator {
        StandardTimeGenerator
    }
}

impl TimeGenerator for StandardTimeGenerator {
    fn get_time(&self) -> Timespec {
        get_time()
    }
}

#[cfg(test)]
#[derive(Clone,Copy,Debug,PartialEq)]
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
