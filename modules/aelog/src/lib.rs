//! log macro for AstrancE os
#![no_std]
extern crate alloc;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt::Write;
use log::*;

pub use log::{Level, Record, log};

//pub type Record<'a> = LogRecord<'a>;

pub static LOG_LEVEL: Level = Level::Debug; //TODO: can be set by config file

pub struct AELogger<'a> {
    appenders: Vec<Box<dyn Appender + 'a>>,
    formatter: Box<Formatter>,
    level_filter: LevelFilter,
}

impl<'a> Default for AELogger<'a> {
    fn default() -> Self {
        Self {
            appenders: Vec::new(),
            formatter: Box::new(default_formatter),
            level_filter: LevelFilter::Info,
        }
    }
}

impl<'a> AELogger<'a> {
    /// add appender to Logger
    /// appenders will be called when [AELogger::log] is called
    pub fn add_appender(&mut self, appender: impl Appender + 'a) -> &mut Self {
        self.appenders.push(Box::new(appender));
        self
    }

    pub fn set_level_filter(&mut self, level: LevelFilter) -> &mut Self {
        self.level_filter = level;
        self
    }

    pub fn set_formatter(
        &mut self,
        formatter: impl Fn(&Record) -> String + Send + Sync + 'static,
    ) -> &mut Self {
        self.formatter = Box::new(formatter);
        self
    }
}

/// log formatter
pub type Formatter = dyn Fn(&log::Record) -> String + Send + Sync;

/// ref: axlog
macro_rules! with_color {
    ($color_code:expr, $fmt:literal $(, $($arg:tt)+)?) => {
            format_args!(
                concat!("\x1b[{}m", $fmt, "\x1b[0m\n"),
                $color_code,
                $( $($arg)+ )?
            )
    };
}

#[repr(u8)]
enum ColorCode {
    Black = 30,
    Red = 31,
    Green = 32,
    Yellow = 33,
    Blue = 34,
    Magenta = 35,
    Cyan = 36,
    White = 37,
    BrightBlack = 90,
    BrightRed = 91,
    BrightGreen = 92,
    BrightYellow = 93,
    BrightBlue = 94,
    BrightMagenta = 95,
    BrightCyan = 96,
    BrightWhite = 97,
}

// 默认格式化器
pub fn default_formatter(record: &log::Record) -> String {
    use core::fmt::Write;
    let mut buf = alloc::string::String::new();
    let level = record.level();
    let args_color = match level {
        Level::Error => ColorCode::Red,
        Level::Warn => ColorCode::Yellow,
        Level::Info => ColorCode::Green,
        Level::Debug => ColorCode::Cyan,
        Level::Trace => ColorCode::BrightBlack,
    };
    let args_color = args_color as u8;

    let file = record.file().unwrap_or("unknown");
    let line = record.line().unwrap_or(0);
    let args = record.args();

    let level = format!("[{level}]");

    write!(
        &mut buf,
        "{}",
        with_color!(args_color, "{:<7} [{}:{}] {}", level, file, line, args)
    )
    .unwrap(); // TODO: handle error
    buf
}

impl Log for AELogger<'_> {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= LOG_LEVEL
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let formatted = (self.formatter)(record);
        for appender in &self.appenders {
            appender.write(&record, formatted.clone());
        }
    }

    fn flush(&self) {
        todo!()
    }
}

pub trait Appender: Send + Sync {
    fn write(&self, record: &Record, formatted: String);
}

pub fn init(logger: &'static AELogger) -> Result<(), SetLoggerError> {
    log::set_logger(logger).map(|()| log::set_max_level(LevelFilter::Info))
}

#[macro_export]
macro_rules! trace {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::log!($crate::Level::Trace, $fmt $(, $($arg)+)?);
    };
}
#[macro_export]
macro_rules! debug {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::log!($crate::Level::Debug, $fmt $(, $($arg)+)?);
    };
}
#[macro_export]
macro_rules! info {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::log!($crate::Level::Info, $fmt $(, $($arg)+)?);
    };
}
#[macro_export]
macro_rules! warn {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::log!($crate::Level::Warn, $fmt $(, $($arg)+)?);
    };
}
#[macro_export]
macro_rules! error {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::log!($crate::Level::Error, $fmt $(, $($arg)+)?);
    };
}
