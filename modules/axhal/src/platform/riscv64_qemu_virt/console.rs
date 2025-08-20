use memory_addr::VirtAddr;

use crate::mem::virt_to_phys;

/// The maximum number of bytes that can be read at once.
const MAX_RW_SIZE: usize = 256;

/// Writes a byte to the console.
pub fn putchar(c: u8) {
    sbi_rt::console_write_byte(c);
}

/// Tries to write bytes to the console from input u8 slice.
/// Returns the number of bytes written.
fn try_write_bytes(bytes: &[u8]) -> usize {
    sbi_rt::console_write(sbi_rt::Physical::new(
        // A maximum of 256 bytes can be written at a time
        // to prevent SBI from disabling IRQs for too long.
        bytes.len().min(MAX_RW_SIZE),
        virt_to_phys(VirtAddr::from_ptr_of(bytes.as_ptr())).as_usize(),
        0,
    ))
    .value
}

/// Writes bytes to the console from input u8 slice.
pub fn write_bytes(bytes: &[u8]) {
    // If the address is from userspace, we need to copy the bytes to kernel space.
    #[cfg(feature = "uspace")]
    if bytes.as_ptr() as usize & (1 << 63) == 0 {
        // Check if the address is valid.
        let kernel_bytes = bytes.to_vec();
        let mut write_len = 0;
        while write_len < kernel_bytes.len() {
            let len = try_write_bytes(&kernel_bytes[write_len..]);
            if len == 0 {
                break;
            }
            write_len += len;
        }
        return;
    }
    let mut write_len = 0;
    while write_len < bytes.len() {
        let len = try_write_bytes(&bytes[write_len..]);
        if len == 0 {
            break;
        }
        write_len += len;
    }
}

/// Reads bytes from the console into the given mutable slice.
/// Returns the number of bytes read.
pub fn read_bytes(bytes: &mut [u8]) -> usize {
    sbi_rt::console_read(sbi_rt::Physical::new(
        bytes.len().min(MAX_RW_SIZE),
        virt_to_phys(VirtAddr::from_mut_ptr_of(bytes.as_mut_ptr())).as_usize(),
        0,
    ))
    .value
}


/*
 *pub fn print_slice_address_raw(data: &mut [u8]) {
 *    let ptr = data.as_mut_ptr();
 *    let addr = ptr as usize;
 *
 *    // 打印前缀
 *    write_bytes(b"Slice address: 0x");
 *
 *    // 将 usize 地址拆分成 u8 字节并打印
 *    // 注意：usize 的大小取决于架构 (32位或64位)
 *    // 这里假设是64位系统，所以拆成8个u8
 *    // 如果是32位系统，只需要4个u8
 *    // 为了通用性，可以根据 core::mem::size_of::<usize>() 判断
 *    let num_bytes = core::mem::size_of::<usize>();
 *
 *    // 遍历每个字节，从最高位开始
 *    for i in (0..num_bytes).rev() {
 *        let byte = ((addr >> (i * 8)) & 0xFF) as u8;
 *
 *        // 将字节转换为十六进制字符并打印
 *        let high_nibble = (byte >> 4) & 0x0F;
 *        let low_nibble = byte & 0x0F;
 *
 *        let hex_char_high = if high_nibble < 10 {
 *            b'0' + high_nibble
 *        } else {
 *            b'a' + (high_nibble - 10)
 *        };
 *        let hex_char_low = if low_nibble < 10 {
 *            b'0' + low_nibble
 *        } else {
 *            b'a' + (low_nibble - 10)
 *        };
 *
 *        write_bytes(&[hex_char_high]);
 *        write_bytes(&[hex_char_low]);
 *    }
 *    write_bytes(b"\n");
 *}
 */
