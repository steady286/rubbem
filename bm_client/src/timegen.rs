use std::time::SystemTime;

#[derive(Clone,Copy)]
pub enum TimeType {
    #[cfg_attr(not(test), allow(dead_code))]
    Fixed(SystemTime),
    Real
}

pub fn get_time(time_type: &TimeType) -> SystemTime {
    match time_type {
        &TimeType::Fixed(time) => time,
        &TimeType::Real => SystemTime::now()
    }
}
