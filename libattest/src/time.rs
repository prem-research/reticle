use std::time::SystemTime;

/// Current wall-clock time. `std::time::SystemTime::now()` panics on
/// wasm32-unknown-unknown, so use this instead.
#[cfg(target_arch = "wasm32")]
pub fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        + web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
}

/// Current wall-clock time. `std::time::SystemTime::now()` panics on
/// wasm32-unknown-unknown, so use this instead.
#[cfg(not(target_arch = "wasm32"))]
pub fn now() -> SystemTime {
    SystemTime::now()
}
