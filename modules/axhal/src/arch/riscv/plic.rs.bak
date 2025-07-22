use core::num::NonZeroU32;
use core::ptr::NonNull;

// Import necessary items from tock_registers
use tock_registers::{
    interfaces::{Readable, Writeable},
    register_structs,
    registers::{ReadOnly, ReadWrite},
};

use kspin::SpinNoIrq;
use lazyinit::LazyInit;

// Import traits from a separate file
//use crate::plic::traits::{CpuContext, IrqIdentifier};

/// Trait for enums of external interrupt sources.
pub trait IrqIdentifier: Copy {
    /// The unique numerical identifier of the interrupt source.
    fn get_id(&self) -> NonZeroU32;
}

/// A CPU context represents a privilege mode on a specific hardware thread (Hart).
pub trait CpuContext: Copy {
    /// Returns the numerical index of this CPU context as understood by the PLIC.
    fn get_index(&self) -> usize;
}

/// Maximum number of interrupt sources supported by PLIC.
const MAX_IRQ_SOURCES: usize = 1024;
/// Maximum number of CPU contexts supported by PLIC.
const MAX_CPU_CONTEXTS: usize = 15872;

const U32_BITS: usize = u32::BITS as usize;

// --- Common IRQ IDs (for convenience, these are often platform-specific but can be kept here if common) ---
// For now, let's keep them here as they are general IRQ IDs, not base addresses.
pub const UART0_IRQ_ID: u32 = 10;
pub const VIRTIO_BLK_IRQ_ID: u32 = 1;

// --- Register Block Definitions using register_structs! ---

// Definition for context-local registers (Priority Threshold, Claim/Complete)
register_structs! {
    #[allow(non_snake_case)]
    ContextSpecificRegs {
        /// Priority Threshold for this context.
        (0x0000 => PriorityThreshold: ReadWrite<u32>),
        /// Interrupt Claim/Complete Register for this context.
        (0x0004 => ClaimComplete: ReadWrite<u32>),
        (0x0008 => _reserved_0),
        (0x1000 => @END), // Each context block is 4KB aligned
    }
}

// Definition for interrupt enable registers for a single context
register_structs! {
    #[allow(non_snake_case)]
    IrqEnablePerContext {
        /// Interrupt Enable bits for sources 0 to MAX_IRQ_SOURCES-1.
        /// Each u32 covers 32 IRQ sources.
        (0x00 => EnableBits: [ReadWrite<u32>; MAX_IRQ_SOURCES / U32_BITS]),
        (0x80 => @END), // 32 * 4 bytes = 128 bytes = 0x80
    }
}

// Definition for the entire PLIC register map
register_structs! {
    #[allow(non_snake_case)]
    PlicRegisterMap {
        /// Interrupt Source Priority Registers (one for each source).
        (0x000000 => IrqPriorities: [ReadWrite<u32>; MAX_IRQ_SOURCES]),
        /// Interrupt Pending Registers (each bit indicates pending status).
        (0x001000 => IrqPending: [ReadOnly<u32>; MAX_IRQ_SOURCES / U32_BITS]),
        (0x001080 => _reserved_0),
        /// Interrupt Enable Registers, indexed by context.
        (0x002000 => ContextEnables: [IrqEnablePerContext; MAX_CPU_CONTEXTS]),
        (0x1F2000 => _reserved_1), // Gap between enable registers and context-specific registers
        /// Context-specific registers (Threshold and Claim/Complete), indexed by context.
        (0x200000 => ContextRegs: [ContextSpecificRegs; MAX_CPU_CONTEXTS]),
        (0x4000000 => @END), // End of PLIC memory map
    }
}

/// Represents the Platform-Level Interrupt Controller.
/// This structure provides methods to interact with PLIC registers.
pub struct InterruptController {
    // We use a NonNull pointer to the PlicRegisterMap to access the registers.
    // This is how tock-registers expects to be used for memory-mapped devices.
    register_map: NonNull<PlicRegisterMap>,
}

// Safety: PLIC registers are memory-mapped, and accesses are synchronized via Mutex.
unsafe impl Send for InterruptController {}
unsafe impl Sync for InterruptController {}

impl InterruptController {
    /// Creates a new instance of the InterruptController from the base address.
    ///
    /// # Safety
    /// `base_addr` must be a valid, non-null memory-mapped base address for a PLIC.
    pub const unsafe fn new(base_addr: usize) -> Self {
        Self {
            // Cast the raw address to a NonNull pointer of our PlicRegisterMap type.
            register_map: NonNull::new_unchecked(base_addr as *mut PlicRegisterMap),
        }
    }

    /// Helper to get a reference to the underlying PlicRegisterMap.
    #[inline(always)]
    fn regs(&self) -> &PlicRegisterMap {
        // Safety: The `register_map` is guaranteed to be non-null and point to a valid PLIC.
        unsafe { self.register_map.as_ref() }
    }

    /// Initializes a specific CPU context for interrupt handling.
    /// This typically involves setting its priority threshold to allow all interrupts.
    pub fn initialize_context<C>(&self, context: C)
    where
        C: CpuContext,
    {
        let ctx_idx = context.get_index();
        self.regs().ContextRegs[ctx_idx].PriorityThreshold.set(0);
    }

    /// Assigns a priority level to an interrupt source.
    ///
    /// A priority of `0` effectively disables the interrupt source.
    /// The lowest active priority is `1`.
    ///
    /// # Arguments
    /// * `source` - The identifier of the interrupt source.
    /// * `priority_value` - The priority level (0 for disabled, 1+ for active).
    #[inline]
    pub fn assign_irq_priority<S>(&self, source: S, priority_value: u32)
    where
        S: IrqIdentifier,
    {
        let irq_id = source.get_id().get() as usize;
        self.regs().IrqPriorities[irq_id].set(priority_value);
    }

    /// Retrieves the current priority level of an interrupt source.
    #[inline]
    pub fn retrieve_irq_priority<S>(&self, source: S) -> u32
    where
        S: IrqIdentifier,
    {
        let irq_id = source.get_id().get() as usize;
        self.regs().IrqPriorities[irq_id].get()
    }

    /// Probes the maximum priority value supported by the PLIC for a given source.
    /// This is done by writing all ones and reading back the effective value.
    #[inline]
    pub fn probe_max_priority<S>(&self, source: S) -> u32
    where
        S: IrqIdentifier,
    {
        let irq_id = source.get_id().get() as usize;
        let reg = &self.regs().IrqPriorities[irq_id];
        reg.set(!0); // Write all ones
        reg.get() // Read back effective value
    }

    /// Checks if a specific interrupt source is currently pending.
    #[inline]
    pub fn is_irq_pending<S>(&self, source: S) -> bool
    where
        S: IrqIdentifier,
    {
        let (group_idx, bit_offset) = get_group_and_bit_offset(source.get_id().get() as usize);
        self.regs().IrqPending[group_idx].get() & (1 << bit_offset) != 0
    }

    /// Activates (enables) an interrupt source for a specific CPU context.
    #[inline]
    pub fn activate_irq<S, C>(&self, source: S, context: C)
    where
        S: IrqIdentifier,
        C: CpuContext,
    {
        let ctx_idx = context.get_index();
        let (group_idx, bit_offset) = get_group_and_bit_offset(source.get_id().get() as usize);

        let enable_reg = &self.regs().ContextEnables[ctx_idx].EnableBits[group_idx];
        let current_value = enable_reg.get();
        enable_reg.set(current_value | (1 << bit_offset));
        self.assign_irq_priority(source, 6);
        warn!(
            "Register PLIC! {:?}, {current_value}, group_idx : {group_idx}, bit_offset : {bit_offset}",
            source.get_id()
        );
    }

    /// Deactivates (disables) an interrupt source for a specific CPU context.
    #[inline]
    pub fn deactivate_irq<S, C>(&self, source: S, context: C)
    where
        S: IrqIdentifier,
        C: CpuContext,
    {
        let ctx_idx = context.get_index();
        let (group_idx, bit_offset) = get_group_and_bit_offset(source.get_id().get() as usize);

        let enable_reg = &self.regs().ContextEnables[ctx_idx].EnableBits[group_idx];
        let current_value = enable_reg.get();
        enable_reg.set(current_value & !(1 << bit_offset));
    }

    /// Checks if an interrupt source is active (enabled) for a specific CPU context.
    #[inline]
    pub fn is_irq_active<S, C>(&self, source: S, context: C) -> bool
    where
        S: IrqIdentifier,
        C: CpuContext,
    {
        let ctx_idx = context.get_index();
        let (group_idx, bit_offset) = get_group_and_bit_offset(source.get_id().get() as usize);

        self.regs().ContextEnables[ctx_idx].EnableBits[group_idx].get() & (1 << bit_offset) != 0
    }

    /// Sets the priority threshold for a specific CPU context.
    /// Only interrupts with priority *greater than* the threshold will be signaled.
    #[inline]
    pub fn set_context_threshold<C>(&self, context: C, threshold_value: u32)
    where
        C: CpuContext,
    {
        let ctx_idx = context.get_index();
        self.regs().ContextRegs[ctx_idx]
            .PriorityThreshold
            .set(threshold_value);
    }

    /// Gets the current priority threshold for a specific CPU context.
    #[inline]
    pub fn get_context_threshold<C>(&self, context: C) -> u32
    where
        C: CpuContext,
    {
        let ctx_idx = context.get_index();
        self.regs().ContextRegs[ctx_idx].PriorityThreshold.get()
    }

    /// Probes the maximum threshold value supported by the PLIC for a given context.
    #[inline]
    pub fn probe_max_threshold<C>(&self, context: C) -> u32
    where
        C: CpuContext,
    {
        let ctx_idx = context.get_index();
        let reg = &self.regs().ContextRegs[ctx_idx].PriorityThreshold;
        reg.set(!0); // Write all ones
        reg.get() // Read back effective value
    }

    /// Claims the highest-priority pending interrupt for a specific CPU context.
    /// Returns the ID of the claimed interrupt, or `None` if no interrupt is pending.
    #[inline]
    pub fn fetch_pending_irq<C>(&self, context: C) -> Option<NonZeroU32>
    where
        C: CpuContext,
    {
        let ctx_idx = context.get_index();
        NonZeroU32::new(self.regs().ContextRegs[ctx_idx].ClaimComplete.get())
    }

    /// Completes the handling of a previously claimed interrupt for a specific CPU context.
    /// This signals to the PLIC that the interrupt has been processed and can be deasserted.
    #[inline]
    pub fn confirm_irq_handled<C, S>(&self, context: C, source: S)
    where
        C: CpuContext,
        S: IrqIdentifier,
    {
        let ctx_idx = context.get_index();
        self.regs().ContextRegs[ctx_idx]
            .ClaimComplete
            .set(source.get_id().get());
    }

    pub fn print_plic_status(&self, context_index: usize) {
        info!("\n--- PLIC Status for Context {} ---", context_index);

        // 1. 打印优先级阈值
        let threshold = self.regs().ContextRegs[context_index]
            .PriorityThreshold
            .get();
        info!("  Priority Threshold: {}", threshold);

        // 2. 打印第一个中断源的优先级 (示例)
        if context_index < MAX_IRQ_SOURCES {
            let prio = self.regs().IrqPriorities[context_index].get();
            info!("  Priority of IRQ {}: {}", context_index, prio);
        }

        // 3. 打印第一个中断挂起组的状态 (示例)
        if !self.regs().IrqPending.is_empty() {
            let pending_group0 = self.regs().IrqPending[0].get();
            info!("  IRQ Pending Group 0: 0x{:08x}", pending_group0);
            // 你可以进一步解析 pending_group0 来查看具体哪个位被设置了
            for i in 0..32 {
                if (pending_group0 >> i) & 1 != 0 {
                    info!("    IRQ {} is pending", i);
                }
            }
        }

        // 4. 打印第一个上下文的 IRQ 启用状态 (示例)
        let enables_group0 = self.regs().ContextEnables[context_index].EnableBits[0].get();
        info!(
            "  IRQ Enable Group 0 for Context {}: 0x{:08x}",
            context_index, enables_group0
        );
        // 你可以进一步解析 enables_group0 来查看具体哪个位被设置了
        for i in 0..32 {
            if (enables_group0 >> i) & 1 != 0 {
                info!("    IRQ {} is enabled for Context {}", i, context_index);
            }
        }

        info!("----------------------------------\n");
    }
}

/// Helper function to calculate the u32 group index and bit offset for an IRQ ID.
#[inline(always)]
fn get_group_and_bit_offset(irq_id: usize) -> (usize, usize) {
    let group_idx = irq_id / U32_BITS;
    let bit_offset = irq_id % U32_BITS;
    (group_idx, bit_offset)
}

// --- Global PLIC instance management ---

// The global instance itself will still be here, but its initialization
// will depend on the platform-specific base address.
pub static GLOBAL_PLIC_CONTROLLER: LazyInit<SpinNoIrq<InterruptController>> = LazyInit::new();

/// Initializes the global PLIC controller instance.
///
/// # Arguments
/// * `plic_base_address` - The base memory address of the PLIC for the current platform.
///
/// # Safety
/// This function must be called exactly once during system initialization.
/// `plic_base_address` must point to a valid PLIC memory region.
pub unsafe fn initialize_global_plic(plic_base_address: usize) {
    GLOBAL_PLIC_CONTROLLER.init_once(SpinNoIrq::new(unsafe {
        InterruptController::new(plic_base_address)
    }));
}
