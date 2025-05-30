#[macro_use]
mod macros;

mod context;
mod trap;

use memory_addr::{PhysAddr, VirtAddr};
use riscv::asm;
use riscv::register::{satp, sstatus, stvec};

#[cfg(feature = "uspace")]
pub use self::context::UspaceContext;
pub use self::context::{GeneralRegisters, TaskContext, TrapFrame};

/// Allows the current CPU to respond to interrupts.
#[inline]
pub fn enable_irqs() {
    unsafe { sstatus::set_sie() }
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

/// 交换当前栈指针(sp)和`sscratch`的值，返回旧的栈指针
///
/// # Safety
/// - 调用者必须确保`sp`是有效且对齐的栈地址
/// - 必须在正确的上下文（如中断/异常处理）中调用
#[inline]
pub unsafe fn exchange_trap_frame(sp: usize) -> usize {
    let old_sp: usize;
    core::arch::asm!(
        "csrrw {old_sp}, sscratch, {new_sp}",  // 交换sscratch和new_sp
        old_sp = out(reg) old_sp,
        new_sp = in(reg) sp,
        options(nostack, preserves_flags)
    );
    old_sp // 返回旧的栈指针
}

/// 读取 `sscratch` 寄存器的值（通常保存内核栈指针或用户态上下文）
///
/// # Safety
/// - 必须在正确的上下文中调用（如中断处理期间）
/// - 读取的值可能无效，调用者需确保其有效性
#[inline(always)] // 强制内联以减少开销
pub unsafe fn read_trap_frame() -> usize {
    let value: usize;
    core::arch::asm!(
        "csrr {}, sscratch",  // 读取 sscratch 到寄存器
        out(reg) value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Initializes CPU states on the current CPU.
///
/// On RISC-V, it sets the trap vector base address.
pub fn cpu_init() {
    unsafe extern "C" {
        fn trap_vector_base();
    }
    set_trap_vector_base(trap_vector_base as usize);
}
