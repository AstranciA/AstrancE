//! Platform-specific PLIC support for riscv64-qemu-virt

use crate::arch::plic::*;
use crate::irq::IrqHandler;
use crate::mem::phys_to_virt;
use axconfig::devices::MMIO_REGIONS;
use core::num::NonZeroU32;
use kspin::SpinNoIrq;
use lazyinit::LazyInit;
use memory_addr::PhysAddr;

/// QEMU virt PLIC基地址在MMIO_REGIONS的第2项
const PLIC_MMIO_INDEX: usize = 1;
const PLIC_BASE_PADDR: usize = MMIO_REGIONS[PLIC_MMIO_INDEX].0;

/// 单核主CPU context（QEMU virt: context 0）
#[derive(Copy, Clone)]
pub struct MainHartContext;
impl CpuContext for MainHartContext {
    fn get_index(&self) -> usize {
        0
    }
}

/// 外部中断号包装
#[derive(Copy, Clone)]
pub struct ExtIrq(pub u32);
impl IrqIdentifier for ExtIrq {
    fn get_id(&self) -> NonZeroU32 {
        // PLIC的IRQ 0保留不用
        NonZeroU32::new(self.0).expect("IRQ 0 is reserved in PLIC")
    }
}

/// 初始化PLIC（主CPU）
pub fn init_primary() {
    unsafe {
        warn!(
            "PLIC_BASE_PADDR: {:x}, vaddr: {:x}",
            PLIC_BASE_PADDR,
            phys_to_virt(PhysAddr::from(PLIC_BASE_PADDR)).as_usize(),
        );
        // 只初始化一次
        if !GLOBAL_PLIC_CONTROLLER.is_inited() {
            GLOBAL_PLIC_CONTROLLER.init_once(SpinNoIrq::new(InterruptController::new(
                phys_to_virt(PhysAddr::from(PLIC_BASE_PADDR)).as_usize(),
            )));
        }
        // 允许所有优先级中断
        GLOBAL_PLIC_CONTROLLER
            .lock()
            .initialize_context(MainHartContext);
        GLOBAL_PLIC_CONTROLLER
            .lock()
            .set_context_threshold(MainHartContext, 0);
    }
}

/// 启用/禁用指定IRQ（只支持外部中断）
pub fn set_enable(irq_num: usize, enabled: bool) {
    let ctrl = GLOBAL_PLIC_CONTROLLER.lock();
    let ext_irq = ExtIrq(irq_num as u32);
    if enabled {
        ctrl.activate_irq(ext_irq, MainHartContext);
    } else {
        ctrl.deactivate_irq(ext_irq, MainHartContext);
    }
}

/// 注册外部中断处理器（直接复用通用表）
pub fn register_handler(irq_num: usize, handler: IrqHandler) -> bool {
    crate::irq::register_handler_common(irq_num, handler)
}

/// 分发外部中断（从PLIC claim）
pub fn dispatch_irq(_unused: usize) {
    warn!("dispatch PLIC!");
    let ctrl = GLOBAL_PLIC_CONTROLLER.lock();
    if let Some(irq_id) = ctrl.fetch_pending_irq(MainHartContext) {
        let irq_num = irq_id.get() as usize;
        crate::irq::dispatch_irq_common(irq_num);
        // 完成中断
        ctrl.confirm_irq_handled(MainHartContext, ExtIrq(irq_num as u32));
    }
}

/// PLIC初始化入口（主CPU）
pub fn init_percpu() {
    use crate::irq::register_irq_handler;
    init_primary();
    for i in 1..12 {
        register_irq_handler(i, || {
            warn!("plic handler");
        });
    }
}
