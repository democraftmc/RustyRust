//! A custom logging macro suite explicitly for RustyRust format rendering.
//! Prepends a colored modular prefix to every recorded entry and appropriately dyes the context body.

/// Prints standard informational strings dynamically utilizing the tracing hook.
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)+) => {
        tracing::info!(
            "{} \x1b[32m{}\x1b[0m",
            "\x1b[1;36m[RustyRust]\x1b[0m",
            format!($($arg)+)
        )
    };
}

/// Prints a yellow-formatted warning entry statically.
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)+) => {
        tracing::warn!(
            "{} \x1b[33m{}\x1b[0m",
            "\x1b[1;36m[RustyRust]\x1b[0m",
            format!($($arg)+)
        )
    };
}

/// Prints aggressive red-formatted fault errors accurately.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)+) => {
        tracing::error!(
            "{} \x1b[1;31m{}\x1b[0m",
            "\x1b[1;36m[RustyRust]\x1b[0m",
            format!($($arg)+)
        )
    };
}

/// Prints invisible-by-default cyan-tinted inner debug streams.
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)+) => {
        tracing::debug!(
            "{} \x1b[1;35m{}\x1b[0m",
            "\x1b[1;36m[RustyRust]\x1b[0m",
            format!($($arg)+)
        )
    };
}
