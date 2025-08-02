use axfdt::*;

#[unsafe(link_section = ".rodata")]
pub static DTB_DATA: &[u8] = include_bytes!("jh7110.dtb");

pub fn platform_init_fdt() -> Result<(), FdtError>{
    axfdt::init_fdt(DTB_DATA)
}
