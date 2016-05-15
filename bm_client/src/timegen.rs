use std::time::SystemTime;

pub trait TimeGenerator : Copy {
    fn get_time(&self) -> SystemTime;
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct StandardTimeGenerator;

impl StandardTimeGenerator {
    pub fn new() -> StandardTimeGenerator {
        StandardTimeGenerator
    }
}

impl TimeGenerator for StandardTimeGenerator {
    fn get_time(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
#[derive(Clone,Copy,Debug,PartialEq)]
pub struct StaticTimeGenerator {
    time: SystemTime
}

#[cfg(test)]
impl StaticTimeGenerator {
    pub fn new(time: SystemTime) -> StaticTimeGenerator {
        StaticTimeGenerator {
            time: time
        }
    }
}

#[cfg(test)]
impl TimeGenerator for StaticTimeGenerator {
    fn get_time(&self) -> SystemTime {
        self.time
    }
}
