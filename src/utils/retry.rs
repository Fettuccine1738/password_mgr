use std::marker::PhantomData;
use std::thread;
use std::time::Duration;

const DEFAULT_MAX_TRIES: u32 = 3;
const DEFAULT_MS_DELAY: u64 = 500; // ms

///
///
pub trait Retry<T> {
    fn retry<F>(&mut self, f: F) -> T
    where
        F: Fn() -> T;
}

#[derive(Clone, Copy, Debug)]
pub struct RetryData {
    pub count_max: u32,
    pub ms_delay: u64,
}

impl Default for RetryData {
    fn default() -> Self {
        Self {
            count_max: DEFAULT_MAX_TRIES,
            ms_delay: DEFAULT_MS_DELAY,
        }
    }
}

/// Designed to run a function `Retry_Data::count_max` times.
#[derive(Default)]
pub struct VoidRetry {
    data: RetryData,
}

impl Retry<()> for VoidRetry {
    fn retry<F>(&mut self, f: F)
    where
        F: Fn() -> (),
        (): Clone,
    {
        let mut count = 0;

        while count < self.data.count_max {
            let _ = f();
            thread::sleep(Duration::from_millis(self.data.ms_delay));
            count += 1;
        }
        ()
    }
}

#[derive(Default)]
pub struct BoolConditionRetry {
    data: RetryData,
}

impl Retry<bool> for BoolConditionRetry {
    fn retry<F>(&mut self, f: F) -> bool
    where
        F: Fn() -> bool,
        bool: Clone,
    {
        let mut count = 0u32;
        let mut result: bool = f(); // result of calling this function the first time

        while !result && count < (self.data.count_max - 1) {
            thread::sleep(Duration::from_millis(self.data.ms_delay));
            result = f();
            count += 1;
        }

        result
    }
}

#[derive(Clone, Debug)]
pub struct ErrCatchingRetry<T, E> {
    data: RetryData,
    _marker: PhantomData<(T, E)>,
}

impl<T, E> Default for ErrCatchingRetry<T, E> {
    fn default() -> Self {
        Self {
            data: Default::default(),
            _marker: Default::default(),
        }
    }
}

impl<T, E> Retry<Result<T, E>> for ErrCatchingRetry<T, E> {
    fn retry<F>(&mut self, f: F) -> Result<T, E>
    where
        F: Fn() -> Result<T, E>,
    {
        let mut count = 0u32;
        let mut result: Result<T, E> = f();

        while result.is_err() && count < self.data.count_max - 1 {
            thread::sleep(Duration::from_millis(self.data.ms_delay));
            result = f();
            count += 1;
        }

        result
    }
}

pub struct BoolOrErrCatchingRetry {
    data: RetryData,
}
