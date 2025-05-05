//! Architecture-specific types and operations.

use memory_addr::{VirtAddr, VirtAddrRange};

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
        pub use self::x86_64::*;
    } else if #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))] {
        mod riscv;
        pub use self::riscv::*;
    } else if #[cfg(target_arch = "aarch64")]{
        mod aarch64;
        pub use self::aarch64::*;
    } else if #[cfg(any(target_arch = "loongarch64"))] {
        mod loongarch64;
        pub use self::loongarch64::*;
    }
}

pub trait ITrapFrame {
    /// Gets the 0th syscall argument.
    fn arg0(&self) -> usize;

    /// Gets the 1st syscall argument.
    fn arg1(&self) -> usize;

    /// Gets the 2nd syscall argument.
    fn arg2(&self) -> usize;

    /// Gets the 3rd syscall argument.
    fn arg3(&self) -> usize;

    /// Gets the 4th syscall argument.
    fn arg4(&self) -> usize;

    /// Gets the 5th syscall argument.
    fn arg5(&self) -> usize;
    /// set return code
    fn set_retval(&mut self, ret_value: usize);

    fn get_sp(&self) -> usize;
    fn set_sp(&mut self, user_sp: usize);

    fn get_ip(&self) -> usize;
    fn set_ip(&mut self, pc: usize);

    fn step_ip(&mut self);
}

pub trait IUspaceContext {
    /// Creates an empty context with all registers set to zero.
    fn empty() -> Self;

    /// Creates a new context with the given entry point, user stack pointer,
    /// and the argument.
    fn new(entry: usize, ustack_top: VirtAddr, arg0: usize) -> Self;

    /// Creates a new context from the given [`TrapFrame`].
    fn with(trap_frame: &TrapFrame) -> Self;

    /// Gets the instruction pointer.
    fn get_ip(&self) -> usize;

    /// Gets the stack pointer.
    fn get_sp(&self) -> usize;

    /// Sets the instruction pointer.
    fn set_ip(&mut self, pc: usize);

    /// Sets the stack pointer.
    fn set_sp(&mut self, sp: usize);

    /// Sets the return value register.
    fn set_retval(&mut self, a0: usize);

    /// Enters user space.
    ///
    /// It restores the user registers and jumps to the user entry point
    /// (saved in `sepc`).
    /// When an exception or syscall occurs, the kernel stack pointer is
    /// switched to `kstack_top`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it changes processor mode and the stack.
    #[unsafe(no_mangle)]
    unsafe fn enter_uspace(&self, kstack_range: VirtAddrRange) -> !;
}

pub trait ITaskContext {
    /// Creates a dummy context for a new task.
    ///
    /// Note the context is not initialized, it will be filled by [`switch_to`]
    /// (for initial tasks) and [`init`] (for regular tasks) methods.
    ///
    /// [`init`]: TaskContext::init
    /// [`switch_to`]: TaskContext::switch_to
     fn new() -> Self;

    /// Initializes the context for a new task, with the given entry point and
    /// kernel stack.
     fn init(&mut self, entry: usize, kstack_top: VirtAddr, tls_area: VirtAddr);

    /// Changes the page table root (`satp` register for riscv64).
    ///
    /// If not set, the kernel page table root is used (obtained by
    /// [`axhal::paging::kernel_page_table_root`][1]).
    /// hl
    ///
    ///
    /// [1]: crate::paging::kernel_page_table_root
    #[cfg(feature = "uspace")]
     fn set_page_table_root(&mut self, satp: memory_addr::PhysAddr);

    /// Switches to another task.
    ///
    /// It first saves the current task's context from CPU to this place, and then
    /// restores the next task's context from `next_ctx` to CPU.
     fn switch_to(&mut self, next_ctx: &Self);
}
