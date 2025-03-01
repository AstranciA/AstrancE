use bitflags::bitflags;
use core::fmt::{self, Write};

use crate::sbi::put_char;

struct Stdout;

bitflags! {
    pub struct LogLevel: u8 {
        const TRACE = 0b00001;
        const DEBUG = 0b00010;
        const INFO  = 0b00100;
        const WARN  = 0b01000;
        const ERROR = 0b10000;
        const ALL   = Self::TRACE.bits() | Self::DEBUG.bits() | Self::INFO.bits() |
                     Self::WARN.bits() | Self::ERROR.bits();
        const DEFAULT = Self::ALL.bits() - Self::DEBUG.bits();
    }
}

//pub static LOG_LEVEL: LogLevel = LogLevel::from_bits_retain(LogLevel::ALL.bits());

/*
 *lazy_static! {
 *    //pub static ref LOG_LEVEL: LogLevel = LogLevel::ALL - LogLevel::DEBUG;
 *    pub static ref LOG_LEVEL: LogLevel = LogLevel::ALL - LogLevel::DEBUG;
 *}
 */

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &c in s.as_ascii().unwrap() {
            put_char(c);
        }
        Ok(())
    }
}

pub fn print(args: fmt::Arguments) {
    Stdout.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!($fmt $(, $($arg)+)?));
    };
}

#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!(, "\n") $(, $($arg)+)?));
    };
}

#[macro_export]
macro_rules! kprint {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!("[kernel] ",$fmt) $(, $($arg)+)?));
    };
}

#[macro_export]
macro_rules! kprintln {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!("[kernel] ",$fmt, "\n") $(, $($arg)+)?));
    };
}

#[macro_export]
macro_rules! log_macro {
    ($level:ident, $color:expr, $fmt:literal $(, $($arg:tt)+)?) => {
        if $crate::config::LOG_LEVEL.contains($crate::console::LogLevel::$level) {
            $crate::console::print(format_args!(
                concat!("\x1b[", $color, "m[kernel] [", stringify!($level), "] ", $fmt, "\x1b[0m\n"),
                $( $($arg)+ )?
            ));
        }
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => (log_macro!(TRACE, "35", $($arg)*));
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => (log_macro!(DEBUG, "32", $($arg)*));
}

#[macro_export]
macro_rules! info2 {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!("\x1b[34m[kernel] [info] ",$fmt, "\x1b[0m\n") $(, $($arg)+)?));
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => (log_macro!(INFO, "34", $($arg)*));
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => (log_macro!(WARN, "33", $($arg)*));
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => (log_macro!(ERROR, "31", $($arg)*));
}
