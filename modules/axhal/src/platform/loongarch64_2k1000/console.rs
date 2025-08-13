use crate::mem::phys_to_virt;
use kspin::SpinNoIrq;
use lazyinit::LazyInit;
use memory_addr::PhysAddr;
use ns16550a::Uart;

const UART_BASE: PhysAddr = pa!(axconfig::devices::UART_PADDR);

static UART: LazyInit<SpinNoIrq<Uart>> = LazyInit::new();

/// Writes bytes to the console from input u8 slice.
pub fn write_bytes(bytes: &[u8]) {
    for &c in bytes {
        let uart = UART.lock();
        while uart.put(c) == None {}
        if c == b'\n' {
            while uart.put(b'\r') == None {}
        }
    }
}

/// Reads bytes from the console into the given mutable slice.
/// Returns the number of bytes read.
pub fn read_bytes(bytes: &mut [u8]) -> usize {
    for (i, byte) in bytes.iter_mut().enumerate() {
        match UART.lock().get() {
            Some(c) => *byte = c,
            None => return i,
        }
    }
    bytes.len()
}

/// Early stage initialization for ns16550a
pub(super) fn init_early() {
    //use ns16550a::*;
    let vaddr = phys_to_virt(UART_BASE);
    let uart = Uart::new(vaddr.as_usize());
    /*
     *uart.init(
     *    WordLength::EIGHT,
     *    StopBits::ONE,
     *    ParityBit::DISABLE,
     *    ParitySelect::ODD,
     *    StickParity::DISABLE,
     *    Break::DISABLE,
     *    DMAMode::MODE0,
     *    Divisor::BAUD115200,
     *);
     */
    UART.init_once(SpinNoIrq::new(uart));
}
