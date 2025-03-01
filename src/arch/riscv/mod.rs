use core::ops::{Deref, DerefMut};
pub mod syscall;

pub type Reg = usize;


#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GPRegs([usize; 32]);

impl Deref for GPRegs {
    type Target = [usize;32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for GPRegs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl GPRegs {
    pub fn empty() -> Self {
        Self([0; 32])
    }

    pub fn sp(&self) -> &Reg {
        &self[2]
    }

    pub fn set_sp(&mut self, sp: Reg) {
        self[2] = sp
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SavedRegs(pub [usize; 12]);

impl Deref for SavedRegs {
    type Target = [usize;12];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SavedRegs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SavedRegs {
    pub fn empty() -> Self {
        Self([0; 12])
    }
}
