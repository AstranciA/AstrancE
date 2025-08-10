use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
};
use axfs::{PROC_ROOT, VfsError, VfsResult, proc::ProcFileGenerator};
use axhal::trap::{IRQ, register_trap_handler};
use core::fmt::Write;
use spin::Mutex; // 假设 axhal::trap 提供了这些

static IRQ_COUNTS: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

pub fn add_irq_count(irq_num: usize) {
    let mut counts = IRQ_COUNTS.lock();
    *counts.entry(irq_num).or_insert(0) += 1;
}

fn get_irq_counts() -> BTreeMap<usize, u64> {
    IRQ_COUNTS.lock().clone()
}

// 示例中断号，请根据实际硬件和中断控制器配置调整
pub const IRQ_TIMER: usize = 5;

#[register_trap_handler(IRQ)]
fn generic_irq_counter_handler(scause: usize) -> bool {
    let exception_code = scause & !(1 << (usize::BITS - 1));
    warn!("{scause:x?} {exception_code:x?}");
    if exception_code == IRQ_TIMER {
        warn!("5");
        add_irq_count(IRQ_TIMER);
    } else {
        warn!("10");
        // TODO: read irq num
        add_irq_count(10);
    }

    true
}

fn generate_interrupts_content() -> VfsResult<String> {
    let mut output = String::new();
    let irq_counts = get_irq_counts();

    for (irq_num, count) in irq_counts.iter() {
        writeln!(&mut output, "{}:        {}", irq_num, count).map_err(|_| VfsError::Io)?;
    }
    Ok(output)
}

fn create_interrupts_file_generator() -> Arc<ProcFileGenerator> {
    Arc::new(|offset: u64, buf: &mut [u8]| -> VfsResult<usize> {
        let full_content = generate_interrupts_content()?;
        let start = offset as usize;
        if start >= full_content.len() {
            return Ok(0);
        }
        let end = (start + buf.len()).min(full_content.len());
        let slice_to_copy = &full_content[start..end];
        buf[..slice_to_copy.len()].copy_from_slice(slice_to_copy.as_bytes());
        Ok(slice_to_copy.len())
    })
}

pub fn init_proc_interrupts() -> VfsResult<()> {
    // Ensure `generic_irq_counter_handler` is properly integrated into your trap handling.
    // The `#[register_trap_handler(IRQ)]` macro should handle the registration.

    let proc_root = PROC_ROOT.clone();
    proc_root.create_dynamic_file("interrupts", create_interrupts_file_generator())?;

    Ok(())
}

