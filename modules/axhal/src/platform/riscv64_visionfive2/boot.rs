use riscv::register::satp;

use axconfig::{TASK_STACK_SIZE, plat::PHYS_VIRT_OFFSET};


#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: [u8; TASK_STACK_SIZE] = [0; TASK_STACK_SIZE];

#[unsafe(link_section = ".data.boot_page_table")]
static mut BOOT_PT_SV39: [u64; 512] = [0; 512];

#[allow(clippy::identity_op)] // (0x0 << 10) here makes sense because it's an address
unsafe fn init_boot_page_table() {
    // 0x0000_0000..0x4000_0000 (通常是 MMIO 区域和一些保留区域)
    // 映射到 0x0000_0000..0x4000_0000
    // 1G block, PPN = 0x0
    BOOT_PT_SV39[0] = (0x0 << 10) | 0xef; // VRWX_GAD flags

    // 0x4000_0000..0x8000_0000 (DRAM 起始部分，包含内核)
    // 映射到 0x4000_0000..0x8000_0000
    // 1G block, PPN = 0x40000 (0x4000_0000 >> 20)
    BOOT_PT_SV39[1] = (0x40000 << 10) | 0xef; // VRWX_GAD flags

    // 0x8000_0000..0xC000_0000 (DRAM 剩余部分)
    // 映射到 0x8000_0000..0xC000_0000
    // 1G block, PPN = 0x80000 (0x8000_0000 >> 20)
    BOOT_PT_SV39[2] = (0x80000 << 10) | 0xef; // VRWX_GAD flags

    // 0xffff_ffc0_0000_0000..0xffff_ffc0_4000_0000 (对应物理地址 0x0..0x4000_0000)
    // 1G block, PPN = 0x0
    BOOT_PT_SV39[0x100] = (0x0 << 10) | 0xef; // VRWX_GAD flags

    // 0xffff_ffc0_4000_0000..0xffff_ffc0_8000_0000 (对应物理地址 0x4000_0000..0x8000_0000)
    // 1G block, PPN = 0x40000 (0x4000_0000 >> 20)
    BOOT_PT_SV39[0x101] = (0x40000 << 10) | 0xef; // VRWX_GAD flags

    // 0xffff_ffc0_8000_0000..0xffff_ffc0_c000_0000 (对应物理地址 0x8000_0000..0xC000_0000)
    // 1G block, PPN = 0x80000 (0x8000_0000 >> 20)
    BOOT_PT_SV39[0x102] = (0x80000 << 10) | 0xef; // VRWX_GAD flags
}

unsafe extern "C" {
    fn _percpu_start();
}


unsafe fn init_mmu() {
    let page_table_root = &raw const BOOT_PT_SV39 as usize;
    satp::set(satp::Mode::Sv39, 0, page_table_root >> 12);
    riscv::asm::sfence_vma_all();
}

/// The earliest entry point for the primary CPU.
#[naked]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn _start() -> ! {
    // PC = 0x8020_0000
    // a0 = hartid
    // a1 = dtb
    core::arch::naked_asm!("
        //mv      s0, a0                  // save hartid
        //mv      s1, a1                  // save DTB pointer
        li      s0, 0
        li      s1, 0
        la      sp, {boot_stack}
        li      t0, {boot_stack_size}
        add     sp, sp, t0              // setup boot stack

        la      gp, {gp}                // initialize gp

        call    {init_boot_page_table}
        call    {init_mmu}              // setup boot page table and enabel MMU

        li      s2, {phys_virt_offset}  // fix up virtual high address
        add     sp, sp, s2

        mv      a0, s0
        mv      a1, s1
        la      a2, {entry}
        add     a2, a2, s2
        jalr    a2                      // call rust_entry(hartid, dtb)
        j       .",
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        boot_stack_size = const TASK_STACK_SIZE,
        boot_stack = sym BOOT_STACK,
        init_boot_page_table = sym init_boot_page_table,
        init_mmu = sym init_mmu,
        entry = sym super::rust_entry,
        gp = sym _percpu_start
    )
}

/// The earliest entry point for secondary CPUs.
#[cfg(feature = "smp")]
#[naked]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn _start_secondary() -> ! {
    // a0 = hartid
    // a1 = SP
    core::arch::naked_asm!("
        mv      s0, a0                  // save hartid
        mv      sp, a1                  // set SP

        call    {init_mmu}              // setup boot page table and enabel MMU

        li      s1, {phys_virt_offset}  // fix up virtual high address
        add     a1, a1, s1
        add     sp, sp, s1

        mv      a0, s0
        la      a1, {entry}
        add     a1, a1, s1
        jalr    a1                      // call rust_entry_secondary(hartid)
        j       .",
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        init_mmu = sym init_mmu,
        entry = sym super::rust_entry_secondary,
    )
}
