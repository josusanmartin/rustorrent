// Small shared helpers.

/// Unstable in-place heapsort. The standard library's sorts are specialised
/// for every call site and cost several kilobytes each; this one stays small
/// while keeping O(n log n) worst-case time and no allocation.
pub fn sort_by<T>(v: &mut [T], mut less: impl FnMut(&T, &T) -> bool) {
    let len = v.len();
    let mut sift = |v: &mut [T], mut root: usize, end: usize| loop {
        let mut child = 2 * root + 1;
        if child >= end {
            break;
        }
        if child + 1 < end && less(&v[child], &v[child + 1]) {
            child += 1;
        }
        if !less(&v[root], &v[child]) {
            break;
        }
        v.swap(root, child);
        root = child;
    };
    for start in (0..len / 2).rev() {
        sift(v, start, len);
    }
    for end in (1..len).rev() {
        v.swap(0, end);
        sift(v, 0, end);
    }
}

pub fn sort_by_key<T, K: Ord>(v: &mut [T], mut key: impl FnMut(&T) -> K) {
    sort_by(v, |a, b| key(a) < key(b));
}

pub fn sort<T: Ord>(v: &mut [T]) {
    sort_by(v, |a, b| a < b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_like_the_standard_library() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for len in [0usize, 1, 2, 3, 7, 16, 100, 1000] {
            let mut values: Vec<u32> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed % 50) as u32
                })
                .collect();
            let mut expected = values.clone();
            expected.sort_unstable();
            sort(&mut values);
            assert_eq!(values, expected);
            sort_by_key(&mut values, |v| std::cmp::Reverse(*v));
            expected.reverse();
            assert_eq!(values, expected);
        }
    }
}

/// `fetch_update` under another name. Rust 1.99 deprecates `fetch_update` for
/// `try_update`, which Rust 1.89 (the minimum) lacks; this is the same
/// compare-exchange loop.
pub(crate) trait AtomicUpdate {
    type Value: Copy;

    fn update_with(
        &self,
        set_order: std::sync::atomic::Ordering,
        fetch_order: std::sync::atomic::Ordering,
        f: impl FnMut(Self::Value) -> Option<Self::Value>,
    ) -> Result<Self::Value, Self::Value>;
}

macro_rules! impl_atomic_update {
    ($($atomic:ty => $value:ty),*) => {$(
        impl AtomicUpdate for $atomic {
            type Value = $value;

            fn update_with(
                &self,
                set_order: std::sync::atomic::Ordering,
                fetch_order: std::sync::atomic::Ordering,
                mut f: impl FnMut($value) -> Option<$value>,
            ) -> Result<$value, $value> {
                let mut prev = self.load(fetch_order);
                while let Some(next) = f(prev) {
                    match self.compare_exchange_weak(prev, next, set_order, fetch_order) {
                        Ok(value) => return Ok(value),
                        Err(actual) => prev = actual,
                    }
                }
                Err(prev)
            }
        }
    )*};
}

impl_atomic_update!(
    std::sync::atomic::AtomicUsize => usize,
    std::sync::atomic::AtomicU32 => u32,
    std::sync::atomic::AtomicU64 => u64
);
