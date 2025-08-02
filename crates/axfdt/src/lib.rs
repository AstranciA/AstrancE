#![no_std]
pub mod structs;

pub use structs::AxFdt;

pub use fdt::*;
use lazyinit::LazyInit;

pub static FDT: LazyInit<Fdt> = LazyInit::new();

pub fn init_fdt(data: &'static [u8]) -> Result<(), FdtError> {
    FDT.init_once(Fdt::new(data)?);
    Ok(())
}
