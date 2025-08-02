use fdt::{Fdt, FdtError};

pub struct AxFdt<'a> {
    pub inner: Fdt<'a>,
}

impl<'a> AxFdt<'a> {
    pub fn new(fdt_data: &'a [u8]) -> Result<Self, FdtError> {
        let fdt = Fdt::new(fdt_data)?;
        Ok(Self { inner: fdt })
    }
}
