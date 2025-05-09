use memory_addr::{VirtAddr, VirtAddrRange};
use riscv::register::sstatus;

use crate::arch::{ITaskContext, ITrapFrame, IUspaceContext};

use super::trap::{fast_trap_cause, riscv_fast_handler};
use core::{arch::naked_asm, ptr::NonNull};
use fast_trap::{ContextExt, FlowContext, FreeTrapStack, soft_trap, soft_trap2, trap_entry};

/// Saved registers when a trap (interrupt or exception) occurs.

impl ITrapFrame for FlowContext {
    fn arg0(&self) -> usize {
        self.a[0]
    }

    fn arg1(&self) -> usize {
        self.a[1]
    }

    fn arg2(&self) -> usize {
        self.a[2]
    }

    fn arg3(&self) -> usize {
        self.a[3]
    }

    fn arg4(&self) -> usize {
        self.a[4]
    }

    fn arg5(&self) -> usize {
        self.a[5]
    }

    fn set_retval(&mut self, ret_value: usize) {
        self.a[0] = ret_value;
    }

    fn get_sp(&self) -> usize {
        self.sp
    }

    fn set_sp(&mut self, user_sp: usize) {
        self.sp = user_sp;
    }

    fn get_ip(&self) -> usize {
        self.pc
    }

    fn set_ip(&mut self, pc: usize) {
        self.pc = pc;
    }

    fn step_ip(&mut self) {
        self.pc += 4;
    }
}

pub struct UspaceContext(pub FlowContext);

impl IUspaceContext for UspaceContext {
    fn empty() -> Self {
        Self(FlowContext::ZERO)
    }

    fn new(entry: usize, ustack_top: VirtAddr, arg0: usize) -> Self {
        let mut context = FlowContext::ZERO;
        context.pc = entry;
        context.sp = ustack_top.into();
        context.a[0] = arg0;
        Self(context)
    }

    fn with(trap_frame: &FlowContext) -> Self {
        Self(trap_frame.clone())
    }

    fn get_ip(&self) -> usize {
        self.0.pc
    }

    fn get_sp(&self) -> usize {
        self.0.sp
    }

    fn set_ip(&mut self, pc: usize) {
        self.0.pc = pc;
    }

    fn set_sp(&mut self, sp: usize) {
        self.0.sp = sp;
    }

    fn set_retval(&mut self, a0: usize) {
        self.0.a[0] = a0;
    }

    #[unsafe(no_mangle)]
    unsafe fn enter_uspace(&self, kstack_range: VirtAddrRange) -> ! {
        use riscv::register::{sepc, sscratch};
        super::disable_irqs();
        let kstack = FreeTrapStack::new(
            kstack_range.to_range(),
            |_| {},
            unsafe { NonNull::new_unchecked(&self.0 as *const _ as *mut _) },
            riscv_fast_handler,
            ContextExt::read(),
        )
        .unwrap();
        let loaded = kstack.load();
        core::mem::forget(loaded);
        const SPIE: usize = 1 << 5;
        const SUM: usize = 1 << 18;
        //core::arch::asm!("csrw sstatus, {sstatus}", SPIE | SUM);
        //sstatus::set_spie();
        core::arch::asm!("csrw sstatus, {sstatus}", sstatus = in(reg) SPIE | SUM );
        let mut ra: usize;
        core::arch::asm!("mv ra, {ra}", ra = out(reg) ra);
        unsafe { soft_trap2(fast_trap_cause::BOOT, self.0.ra) };

        unreachable!();
    }
}

/*
 *pub struct TaskContext {
 *    context: FlowContext,
 *    #[cfg(feature = "uspace")]
 *    pub satp: memory_addr::PhysAddr,
 *}
 *
 *impl ITaskContext for TaskContext {
 *    /// Creates a dummy context for a new task.
 *    ///
 *    /// Note the context is not initialized, it will be filled by [`switch_to`]
 *    /// (for initial tasks) and [`init`] (for regular tasks) methods.
 *    ///
 *    /// [`init`]: TaskContext::init
 *    /// [`switch_to`]: TaskContext::switch_to
 *    fn new() -> Self {
 *        Self {
 *            context: FlowContext::ZERO,
 *            #[cfg(feature = "uspace")]
 *            satp: crate::paging::kernel_page_table_root(),
 *        }
 *    }
 *
 *    /// Initializes the context for a new task, with the given entry point and
 *    /// kernel stack.
 *    fn init(&mut self, entry: usize, kstack_top: VirtAddr, tls_area: VirtAddr) {
 *        self.context.set_sp(kstack_top.as_usize());
 *        self.context.ra = ret_value;
 *        self.context.tp = tls_area.as_usize();
 *    }
 *
 *    /// Changes the page table root (`satp` register for riscv64).
 *    ///
 *    /// If not set, the kernel page table root is used (obtained by
 *    /// [`axhal::paging::kernel_page_table_root`][1]).
 *    /// hl
 *    ///
 *    ///
 *    /// [1]: crate::paging::kernel_page_table_root
 *    #[cfg(feature = "uspace")]
 *    fn set_page_table_root(&mut self, satp: memory_addr::PhysAddr) {
 *        self.satp = satp;
 *    }
 *
 *    /// Switches to another task.
 *    ///
 *    /// It first saves the current task's context from CPU to this place, and then
 *    /// restores the next task's context from `next_ctx` to CPU.
 *    fn switch_to(&mut self, next_ctx: &Self) {
 *        #[cfg(feature = "tls")]
 *        {
 *            self.context.tp = super::read_thread_pointer();
 *            unsafe { super::write_thread_pointer(next_ctx.tp) };
 *        }
 *        #[cfg(feature = "uspace")]
 *        unsafe {
 *            if self.satp != next_ctx.satp {
 *                super::write_page_table_root(next_ctx.satp);
 *            }
 *        }
 *        unsafe {
 *            // TODO: switch FP states
 *            context_switch(self, next_ctx)
 *        }
 *    }
 *}
 */

/// Saved hardware states of a task.
///
/// The context usually includes:
///
/// - Callee-saved registers
/// - Stack pointer register
/// - Thread pointer register (for thread-local storage, currently unsupported)
/// - FP/SIMD registers
///
/// On context switch, current task saves its context from CPU to memory,
/// and the next task restores its context from memory to CPU.
#[allow(missing_docs)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct TaskContext {
    pub ra: usize, // return address (x1)
    pub sp: usize, // stack pointer (x2)

    pub s0: usize, // x8-x9
    pub s1: usize,

    pub s2: usize, // x18-x27
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,

    pub tp: usize,
    /// The `satp` register value, i.e., the page table root.
    #[cfg(feature = "uspace")]
    pub satp: memory_addr::PhysAddr,
    // TODO: FP states
}

impl ITaskContext for TaskContext {
    /// Creates a dummy context for a new task.
    ///
    /// Note the context is not initialized, it will be filled by [`switch_to`]
    /// (for initial tasks) and [`init`] (for regular tasks) methods.
    ///
    /// [`init`]: TaskContext::init
    /// [`switch_to`]: TaskContext::switch_to
    fn new() -> Self {
        Self {
            #[cfg(feature = "uspace")]
            satp: crate::paging::kernel_page_table_root(),
            ..Default::default()
        }
    }

    /// Initializes the context for a new task, with the given entry point and
    /// kernel stack.
    fn init(&mut self, entry: usize, kstack_top: VirtAddr, tls_area: VirtAddr) {
        self.sp = kstack_top.as_usize();
        self.ra = entry;
        self.tp = tls_area.as_usize();
    }

    /// Changes the page table root (`satp` register for riscv64).
    ///
    /// If not set, the kernel page table root is used (obtained by
    /// [`axhal::paging::kernel_page_table_root`][1]).
    /// hl
    ///
    ///
    /// [1]: crate::paging::kernel_page_table_root
    #[cfg(feature = "uspace")]
    fn set_page_table_root(&mut self, satp: memory_addr::PhysAddr) {
        self.satp = satp;
    }

    /// Switches to another task.
    ///
    /// It first saves the current task's context from CPU to this place, and then
    /// restores the next task's context from `next_ctx` to CPU.
    fn switch_to(&mut self, next_ctx: &Self) {
        warn!("switch! satp: {:x} {:x}", self.satp, next_ctx.satp);
        #[cfg(feature = "tls")]
        {
            self.tp = super::read_thread_pointer();
            unsafe { super::write_thread_pointer(next_ctx.tp) };
        }
        #[cfg(feature = "uspace")]
        unsafe {
            if self.satp != next_ctx.satp {
                super::write_page_table_root(next_ctx.satp);
            }
        }
        unsafe {
            // TODO: switch FP states
            context_switch(self, next_ctx);
        }
        warn!("123");
    }
}

#[naked]
unsafe extern "C" fn context_switch(_current_task: &mut TaskContext, _next_task: &TaskContext) {
    core::arch::naked_asm!(
        include_asm_macros!(),
        "
        // save old context (callee-saved registers)
        STR     ra, a0, 0
        STR     sp, a0, 1
        STR     s0, a0, 2
        STR     s1, a0, 3
        STR     s2, a0, 4
        STR     s3, a0, 5
        STR     s4, a0, 6
        STR     s5, a0, 7
        STR     s6, a0, 8
        STR     s7, a0, 9
        STR     s8, a0, 10
        STR     s9, a0, 11
        STR     s10, a0, 12
        STR     s11, a0, 13

        // restore new context
        LDR     s11, a1, 13
        LDR     s10, a1, 12
        LDR     s9, a1, 11
        LDR     s8, a1, 10
        LDR     s7, a1, 9
        LDR     s6, a1, 8
        LDR     s5, a1, 7
        LDR     s4, a1, 6
        LDR     s3, a1, 5
        LDR     s2, a1, 4
        LDR     s1, a1, 3
        LDR     s0, a1, 2
        LDR     sp, a1, 1
        LDR     ra, a1, 0

        ret",
    )
}
