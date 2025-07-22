//! TODO: PLIC

use crate::irq::IrqHandler;
use lazyinit::LazyInit;
use riscv::register::sie;
use crate::platform::riscv64_qemu_virt::plic;

/// `Interrupt` bit in `scause`
pub(super) const INTC_IRQ_BASE: usize = 1 << (usize::BITS - 1);

/// Supervisor software interrupt in `scause`
#[allow(unused)]
pub(super) const S_SOFT: usize = INTC_IRQ_BASE + 1;

/// Supervisor timer interrupt in `scause`
pub(super) const S_TIMER: usize = INTC_IRQ_BASE + 5;

/// Supervisor external interrupt in `scause`
pub(super) const S_EXT: usize = INTC_IRQ_BASE + 9;

static TIMER_HANDLER: LazyInit<IrqHandler> = LazyInit::new();

/// The maximum number of IRQs.
pub const MAX_IRQ_COUNT: usize = 1024;

/// The timer IRQ number (supervisor timer interrupt in `scause`).
pub const TIMER_IRQ_NUM: usize = S_TIMER;

macro_rules! with_cause {
    ($cause: expr, @TIMER => $timer_op: expr, @EXT => $ext_op: expr $(,)?) => {
        match $cause {
            S_TIMER => $timer_op,
            S_EXT => $ext_op,
            _ => panic!("invalid trap cause: {:#x}", $cause),
        }
    };
}

/// Enables or disables the given IRQ.
pub fn set_enable(irq_num: usize, enabled: bool) {
    // 只处理外部中断（PLIC）
    plic::set_enable(irq_num, enabled);
}

/// Registers an IRQ handler for the given IRQ.
///
/// It also enables the IRQ if the registration succeeds. It returns `false` if
/// the registration failed.
pub fn register_handler(scause: usize, handler: IrqHandler) -> bool {
    with_cause!(
        scause,
        @TIMER => {
            // 注册timer handler
            if !TIMER_HANDLER.is_inited() {
                TIMER_HANDLER.init_once(handler);
                true
            } else {
                false
            }
        },
        // @EXT => crate::irq::register_handler_common(scause & !INTC_IRQ_BASE, handler),
        @EXT => {
            panic!("don't use this function to register external interrupt handler")
        }
    )
}

/// Dispatches the IRQ.
///
/// This function is called by the common interrupt handler. It looks
/// up in the IRQ handler table and calls the corresponding handler. If
/// necessary, it also acknowledges the interrupt controller after handling.
pub fn dispatch_irq(scause: usize) {
    warn!("Scause: {:x}", scause);
    with_cause!(
        scause,
        @TIMER => {
            trace!("IRQ: timer");
            TIMER_HANDLER();
        },
        @EXT => plic::dispatch_irq(0), // 0未用，PLIC claim决定实际号
    );
}

pub(super) fn init_percpu() {
    // enable soft interrupts, timer interrupts, and external interrupts
    unsafe {
        sie::set_ssoft();
        sie::set_stimer();
        sie::set_sext();
        sie::set_sext();
    }
    plic::init_percpu();
}
