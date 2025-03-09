use core::panic::PanicInfo;

use crate::{sbi::shutdown, stack_trace::print_stack_trace};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        error!(
            "[kernel] Panicked at {}:{} {}",
            location.file(),
            location.line(),
            info.message()
        );
    } else {
        error!("[kernel] Panicked: {}", info.message());
    }
    /*
     *unsafe {
     *    print_stack_trace();
     *}
     */
    shutdown(true)
}
