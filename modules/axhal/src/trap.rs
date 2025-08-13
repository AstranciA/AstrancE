//! Trap handling.

use linkme::distributed_slice as def_trap_handler;
use memory_addr::VirtAddr;
use page_table_entry::MappingFlags;

pub use linkme::distributed_slice as register_trap_handler;

use crate::arch::TrapFrame;

/// A slice of IRQ handler functions.
#[def_trap_handler]
pub static IRQ: [fn(usize) -> bool];

/// A slice of page fault handler functions.
#[def_trap_handler]
pub static PAGE_FAULT: [fn(VirtAddr, MappingFlags, bool) -> bool];

/// A slice of syscall handler functions.
#[cfg(feature = "uspace")]
#[def_trap_handler]
pub static SYSCALL: [fn(&mut TrapFrame, usize) -> Option<isize>];

#[def_trap_handler]
pub static PRE_TRAP: [fn(&mut TrapFrame, bool) -> bool];

#[def_trap_handler]
pub static POST_TRAP: [fn(&mut TrapFrame, bool) -> bool];

#[allow(unused_macros)]
macro_rules! handle_trap {
    ($trap:ident, $($args:tt)*) => {{
        $crate::trap::$trap.iter().all(|func| func($($args)*))
    }};
}

#[unsafe(no_mangle)]
pub(crate) fn post_trap_callback(tf: &mut TrapFrame, from_user: bool) {
    for cb in crate::trap::POST_TRAP.iter() {
        cb(tf, from_user);
    }
}

/// Call the external syscall handler.
/// Handlers can overlap each other but only one of them can return Some(isize).
#[cfg(feature = "uspace")]
pub(crate) fn handle_syscall(tf: &mut TrapFrame, syscall_num: usize) -> isize {
    let mut result = None;
    let mut result_count: usize = 0;
    let args = [
        tf.arg0(),
        tf.arg1(),
        tf.arg2(),
        tf.arg3(),
        tf.arg4(),
        tf.arg5(),
    ];

    debug!("syscall {:?} with args: {:x?}", syscall_num, args);

    for handler in SYSCALL {
        if let Some(r) = handler(tf, syscall_num) {
            if result_count > 1 {
                panic!("Multiple syscall handlers returned a value");
            }
            result = Some(r);
            result_count += 1;
        }
    }

    if let Some(r) = result {
        debug!("syscall_handler result: {:x?}", r);
        r
    } else {
        error!("unhandled syscall {:?}, args: {args:x?}", syscall_num);
        // 38: ENOSYS
        // TODO: loongarch ENOSYS??
        -38
    }
}

pub(crate) fn pre_trap(tf: &mut TrapFrame, from_user: bool) -> bool {
    let mut result = true;
    for handler in PRE_TRAP {
        if !handler(tf, from_user) {
            result = false;
            break;
        }
    }
    result
}

pub(crate) fn post_trap(tf: &mut TrapFrame, from_user: bool) -> bool {
    let mut result = true;
    for handler in POST_TRAP {
        if !handler(tf, from_user) {
            result = false;
            break;
        }
    }
    result
}
