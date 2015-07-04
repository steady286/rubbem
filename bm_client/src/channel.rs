use std::sync::Arc;
use std::sync::atomic::{AtomicUsize,Ordering};
use std::sync::mpsc::{Receiver,RecvError,Sender,SendError,channel};

pub trait MemorySize {
    fn byte_count(&self) -> usize;
}

pub struct ConstrainedSender<T: MemorySize> {
    current_size: Arc<AtomicUsize>,
    limit: usize,
    sender: Sender<T>
}

impl<T: MemorySize> ConstrainedSender<T> {
    pub fn send(&self, t: T) -> Result<(), SendError<T>> {
        let byte_count = t.byte_count();
        let previous = self.current_size.fetch_add(byte_count, Ordering::SeqCst);

        if previous + byte_count > self.limit {
            return Err(SendError(t));
        }

        self.sender.send(t)
    }
}

pub struct ConstrainedReceiver<T: MemorySize> {
    current_size: Arc<AtomicUsize>,
    receiver: Receiver<T>
}

impl<T: MemorySize> ConstrainedReceiver<T> {
    pub fn recv(&self) -> Result<T, RecvError> {
        let t = try!(self.receiver.recv());
        let byte_count = t.byte_count();

        self.current_size.fetch_sub(byte_count, Ordering::SeqCst);

        Ok(t)
    }
}

pub fn constrained_channel<T: MemorySize>(limit: usize) -> (ConstrainedSender<T>, ConstrainedReceiver<T>) {
    let (tx, rx) = channel();
    let current_size = Arc::new(AtomicUsize::new(0));

    let sender = ConstrainedSender::<T> {
        current_size: current_size.clone(),
        limit: limit,
        sender: tx
    };

    let receiver = ConstrainedReceiver::<T> {
        current_size: current_size,
        receiver: rx
    };

    (sender, receiver)
}
