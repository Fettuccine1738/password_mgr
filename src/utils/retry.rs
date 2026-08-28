use std::marker::PhantomData;
use std::thread;
use std::time::Duration;

const DEFAULT_MAX_TRIES: u32 = 3;
const DEFAULT_MS_DELAY: u64 = 500; // ms

///
///
pub trait Retry<T> {
    fn retry_data(&self) -> &RetryData;

    // fn retry<F>(&mut self, f: F) -> T
    // where
    //     F: FnMut() -> T;

    fn get_tries_max(&self) -> u32 {
        self.retry_data().count_max
    }

    fn get_delay_max(&self) -> u64 {
        self.retry_data().ms_delay
    }

    fn retry<F>(&mut self, mut f: F) -> T 
    where F: FnMut() -> T,
    {
        let max = self.get_tries_max();
        let delay = self.get_delay_max();

        let mut result = f();
        let mut count = 1;

        while count < max {
            thread::sleep(Duration::from_millis(delay));
            result = f();
            count += 1;
        }

        result
    }
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
    fn retry_data(&self) -> &RetryData {
        &self.data
    }
}

#[derive(Default)]
pub struct BoolConditionRetry {
    data: RetryData,
}

impl Retry<bool> for BoolConditionRetry {
    fn retry<F>(&mut self, mut f: F) -> bool
    where
        F: FnMut() -> bool,
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

    fn retry_data(&self) -> &RetryData {
        &self.data
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
    fn retry_data(&self) -> &RetryData {
        &self.data
    }

    fn retry<F>(&mut self, mut f: F) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
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

// pub struct BoolOrErrCatchingRetry {
//     data: RetryData,
// }
