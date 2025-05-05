#[macro_use]
mod macros;

mod trap;

use core::ptr::NonNull;

use memory_addr::{PhysAddr, VirtAddr};
use riscv::asm;
use riscv::register::{satp, sscratch, sstatus, stvec};

#[cfg(feature = "uspace")]
cfg_if::cfg_if! {
    if #[cfg(feature = "fast-trap")] {
        mod fast_context;
        pub use fast_trap::FlowContext as TrapFrame;
        use fast_trap::FreeTrapStack;
        pub use fast_context::{UspaceContext, TaskContext};
        use trap::riscv_fast_handler;
    } else {
        mod context;
        pub use context::{TrapFrame, UspaceContext, TaskContext, GeneralRegisters};
    }
}

/// Allows the current CPU to respond to interrupts.
//#[inline]
pub fn enable_irqs() {
    unsafe { sstatus::set_sie() };
}

/// Makes the current CPU to ignore interrupts.
#[inline]
pub fn disable_irqs() {
    unsafe { sstatus::clear_sie() }
}

/// Returns whether the current CPU is allowed to respond to interrupts.
#[inline]
pub fn irqs_enabled() -> bool {
    sstatus::read().sie()
}

/// Relaxes the current CPU and waits for interrupts.
///
/// It must be called with interrupts enabled, otherwise it will never return.
#[inline]
pub fn wait_for_irqs() {
    riscv::asm::wfi()
}

/// Halt the current CPU.
#[inline]
pub fn halt() {
    disable_irqs();
    riscv::asm::wfi() // should never return
}

/// Reads the register that stores the current page table root.
///
/// Returns the physical address of the page table root.
#[inline]
pub fn read_page_table_root() -> PhysAddr {
    pa!(satp::read().ppn() << 12)
}

/// Writes the register to update the current page table root.
///
/// # Safety
///
/// This function is unsafe as it changes the virtual memory address space.
pub unsafe fn write_page_table_root(root_paddr: PhysAddr) {
    let old_root = read_page_table_root();
    trace!("set page table root: {:#x} => {:#x}", old_root, root_paddr);
    if old_root != root_paddr {
        satp::set(satp::Mode::Sv39, 0, root_paddr.as_usize() >> 12);
        asm::sfence_vma_all();
    }
}

/// Flushes the TLB.
///
/// If `vaddr` is [`None`], flushes the entire TLB. Otherwise, flushes the TLB
/// entry that maps the given virtual address.
#[inline]
pub fn flush_tlb(vaddr: Option<VirtAddr>) {
    unsafe {
        if let Some(vaddr) = vaddr {
            asm::sfence_vma(0, vaddr.as_usize())
        } else {
            asm::sfence_vma_all();
        }
    }
}

/// Writes Supervisor Trap Vector Base Address Register (`stvec`).
#[inline]
pub fn set_trap_vector_base(stvec: usize) {
    unsafe { stvec::write(stvec, stvec::TrapMode::Direct) }
}

/// Reads the thread pointer of the current CPU.
///
/// It is used to implement TLS (Thread Local Storage).
#[inline]
pub fn read_thread_pointer() -> usize {
    let tp;
    unsafe { core::arch::asm!("mv {}, tp", out(reg) tp) };
    tp
}

/// Writes the thread pointer of the current CPU.
///
/// It is used to implement TLS (Thread Local Storage).
///
/// # Safety
///
/// This function is unsafe as it changes the CPU states.
#[inline]
pub unsafe fn write_thread_pointer(tp: usize) {
    core::arch::asm!("mv tp, {}", in(reg) tp)
}

static mut KERNEL_STACK: [u8; 4096] = [0; 4096];
/// Initializes CPU states on the current CPU.
///
/// On RISC-V, it sets the trap vector base address.
#[allow(static_mut_refs)]
pub fn cpu_init() {
    cfg_if::cfg_if! {
        if #[cfg(feature = "fast-trap")] {
            use fast_trap::ContextExt;
            static mut TRAP_FRAME: TrapFrame = TrapFrame::ZERO;

            let init_trap = FreeTrapStack::new(
                unsafe{(KERNEL_STACK.as_ptr() as usize)..(KERNEL_STACK.as_ptr() as usize + 4096) },
                |_| {},
                unsafe {NonNull::new_unchecked(&TRAP_FRAME as *const _ as *mut _)},
                riscv_fast_handler,
                ContextExt::read()
            ).unwrap();
            sscratch::write(init_trap.ptr());
            core::mem::forget(init_trap);
            set_trap_vector_base(fast_trap::trap_entry as usize);
        } else {
            unsafe extern "C" {
                fn trap_vector_base();
            }
            set_trap_vector_base(trap_vector_base as usize);
        }
    }
}
