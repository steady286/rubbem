use super::{Message,ObjectData,VersionData};
use super::pow::{ProofOfWork,VerifyError,network_pow_config};
use config::Config;
use std::time::{Duration,SystemTime};
use timegen::TimeType;

pub enum MessageVerifierError {
    OurNonce,
    OldVersion,
    NoClockSync,
    UnacceptablePow(VerifyError)
}

impl From<VerifyError> for MessageVerifierError {
    fn from(err: VerifyError) -> MessageVerifierError {
        MessageVerifierError::UnacceptablePow(err)
    }
}

pub struct MessageVerifier {
    config: Config,
    time_type: TimeType
}

impl MessageVerifier {
    pub fn new(config: &Config, time_type: TimeType) -> MessageVerifier {
        MessageVerifier {
            config: config.clone(),
            time_type: time_type
        }
    }

    pub fn verify(&self, message: &Message) -> Result<(), MessageVerifierError> {
        match message {
            &Message::Version(VersionData { nonce, version, timestamp, .. }) => {
                self.check_nonce(nonce)?;
                self.check_version_number(version)?;
                self.check_clock_difference(timestamp)?;
                Ok(())
            },
            &Message::Object(ref object_data @ ObjectData { .. }) => {
                self.check_pow(object_data)?;
                Ok(())
            },
            _ => Ok(())
        }
    }

    fn check_nonce(&self, their_nonce: u64) -> Result<(), MessageVerifierError> {
        let our_nonce = self.config.nonce();
        if their_nonce == our_nonce {
            return Err(MessageVerifierError::OurNonce);
        }

        Ok(())
    }

    fn check_version_number(&self, version: u32) -> Result<(), MessageVerifierError> {
        match version {
            0..=1 => Err(MessageVerifierError::OldVersion),
            _ => Ok(())
        }
    }

    fn check_clock_difference(&self, their_time: SystemTime) -> Result<(), MessageVerifierError> {
        let difference = match their_time.elapsed() {
            Ok(duration) => duration,
            Err(system_time_error) => system_time_error.duration()
        };

        if difference > Duration::from_secs(3600) {
            return Err(MessageVerifierError::NoClockSync);
        }

        Ok(())
    }

    fn check_pow(&self, object_data: &ObjectData) -> Result<(), MessageVerifierError> {
        let pow_config = network_pow_config();
        let pow = ProofOfWork::new(self.time_type);
        pow.verify(object_data, pow_config)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageVerifier,MessageVerifierError};
    use config::Config;
    use message::{Message,Object,ObjectData,VersionData};
    use message::pow::VerifyError;
    use net::to_socket_addr;
    use std::time::{Duration,SystemTime,UNIX_EPOCH};
    use timegen::TimeType;

    #[test]
    fn test_normal_version() {
        let input = Message::Version(get_version_data());
        assert!(run_test(input).is_ok());
    }

    #[test]
    fn test_get_version_with_low_version_number() {
        let normal_version = get_version_data();
        let input = Message::Version(VersionData { version: 2, .. normal_version });

        let result = run_test(input);

        match result {
            Err(MessageVerifierError::OldVersion) => {},
            _ => panic!("Expected failure due to low version number")
        }
    }

    #[test]
    fn test_get_version_with_slow_clock() {
        let slow_clock = SystemTime::now() - Duration::from_secs(5000);

        let normal_version = get_version_data();
        let input = Message::Version(VersionData { timestamp: slow_clock, .. normal_version });

        let result = run_test(input);

        match result {
            Err(MessageVerifierError::NoClockSync) => {},
            _ => panic!("Expected failure due to their clock too slow")
        }
    }

    #[test]
    fn test_get_version_with_fast_clock() {
        let fast_clock = SystemTime::now() + Duration::from_secs(5000);

        let normal_version = get_version_data();
        let input = Message::Version(VersionData { timestamp: fast_clock, .. normal_version });

        let result = run_test(input);

        match result {
            Err(MessageVerifierError::NoClockSync) => {},
            _ => panic!("Expected failure due to their clock too fast")
        }
    }

    fn get_version_data() -> VersionData {
        VersionData {
            version: 3,
            services: 1,
            timestamp: SystemTime::now(),
            addr_recv: to_socket_addr("127.0.0.1:8555"),
            addr_from: to_socket_addr("127.0.0.1:8444"),
            nonce: 0x0102030405060708,
            user_agent: "test".to_string(),
            streams: vec![ 1 ]
        }
    }

    #[test]
    fn test_object_with_invalid_pow_is_rejected() {
        let input = Message::Object(get_object_data());
        let result = run_test(input);

        match result {
            Err(MessageVerifierError::UnacceptablePow(VerifyError::UnacceptableProof)) => {},
            _ => panic!("Expected failure due to invalid POW")
        }
    }

    #[test]
    fn test_object_with_valid_pow_is_accepted() {
        let normal_object = get_object_data();
        let input = Message::Object(ObjectData { nonce: 899113, .. normal_object });

        assert!(run_test(input).is_ok());
    }

    #[test]
    fn test_object_with_too_short_ttl_is_rejected() {
        let normal_object = get_object_data();
        let day_before = UNIX_EPOCH - Duration::from_secs(86400);
        let input = Message::Object(ObjectData { expiry: day_before, .. normal_object });
        let result = run_test(input);

        match result {
            Err(MessageVerifierError::UnacceptablePow(VerifyError::ObjectAlreadyDied)) => {},
            _ => panic!("Expected failure due to too short ttl")
        }
    }

    #[test]
    fn test_object_with_too_long_ttl_is_rejected() {
        let normal_object = get_object_data();
        let thirty_days_after = UNIX_EPOCH + Duration::from_secs(2592000);
        let input = Message::Object(ObjectData { expiry: thirty_days_after, .. normal_object });
        let result = run_test(input);

        match result {
            Err(MessageVerifierError::UnacceptablePow(VerifyError::ObjectLivesTooLong)) => {},
            _ => panic!("Expected failure due to too long ttl")
        }
    }

    fn get_object_data() -> ObjectData {
        ObjectData {
            nonce: 1,
            expiry: UNIX_EPOCH + Duration::from_secs(86400), // a day later
            version: 1,
            stream: 1,
            object: Object::Msg { encrypted: (vec![1, 2, 3]) }
        }
    }

    fn run_test(input: Message) -> Result<(), MessageVerifierError> {
        let config = Config::new();
        let verifier = MessageVerifier::new(&config, TimeType::Fixed(UNIX_EPOCH));

        let result = verifier.verify(&input);

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }
}
