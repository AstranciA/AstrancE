use crate::SyscallResult;
use arceos_posix_api::{self as api, ctypes};
use core::ffi::c_int;
use core::ffi::c_void;

#[cfg(feature = "net")]
#[inline]
pub fn sys_socket(domain: c_int, socktype: c_int, protocol: c_int) -> SyscallResult {
    api::sys_socket(domain, socktype, protocol).to_linux_result()
}
#[cfg(feature = "net")]
#[inline]
pub fn sys_bind(
    socket_fd: c_int,
    addr: *const ctypes::sockaddr,
    addrlen: ctypes::socklen_t,
) -> SyscallResult {
    api::sys_bind(socket_fd, addr, addrlen).to_linux_result()
}
#[cfg(feature = "net")]
// Socket connection
#[inline]
pub fn sys_connect(
    socket_fd: c_int,
    addr: *const ctypes::sockaddr,
    addrlen: ctypes::socklen_t,
) -> SyscallResult {
    api::sys_connect(socket_fd, addr, addrlen).to_linux_result()
}
#[cfg(feature = "net")]
// Data sending with address
#[inline]
pub fn sys_sendto(
    socket_fd: c_int,
    buf: *const c_void,
    len: usize,
    _flag: c_int,
    addr: *const ctypes::sockaddr,
    addrlen: ctypes::socklen_t,
) -> SyscallResult {
    api::sys_sendto(socket_fd, buf, len, 0, addr, addrlen).to_linux_result()
}
#[cfg(feature = "net")]
// Data sending (connected socket)
#[inline]
pub fn sys_send(socket_fd: c_int, buf: *const c_void, len: usize, _flag: c_int) -> SyscallResult {
    api::sys_send(socket_fd, buf, len, 0).to_linux_result()
}
#[cfg(feature = "net")]
// Data receiving with address
#[inline]
pub unsafe fn sys_recvfrom(
    socket_fd: c_int,
    buf: *mut c_void,
    len: usize,
    _flag: c_int,
    addr: *mut ctypes::sockaddr,
    addrlen: *mut ctypes::socklen_t,
) -> SyscallResult {
    unsafe { api::sys_recvfrom(socket_fd, buf, len, 0, addr, addrlen) }.to_linux_result()
}
#[cfg(feature = "net")]
// Data receiving (connected socket)
#[inline]
pub fn sys_recv(socket_fd: c_int, buf: *mut c_void, len: usize, _flag: c_int) -> SyscallResult {
    api::sys_recv(socket_fd, buf, len, 0).to_linux_result()
}
#[cfg(feature = "net")]
// Socket listening
#[inline]
pub fn sys_listen(socket_fd: c_int, backlog: c_int) -> SyscallResult {
    api::sys_listen(socket_fd, backlog).to_linux_result()
}
#[cfg(feature = "net")]
// Connection acceptance
#[inline]
pub unsafe fn sys_accept(
    socket_fd: c_int,
    addr: *mut ctypes::sockaddr,
    addrlen: *mut ctypes::socklen_t,
) -> SyscallResult {
    unsafe { api::sys_accept(socket_fd, addr, addrlen) }.to_linux_result()
}
#[cfg(feature = "net")]
// Socket shutdown
#[inline]
pub fn sys_shutdown(socket_fd: c_int, _how: c_int) -> SyscallResult {
    api::sys_shutdown(socket_fd, 0).to_linux_result()
}
#[cfg(feature = "net")]
// Socket address query
#[inline]
pub unsafe fn sys_getsockname(
    socket_fd: c_int,
    addr: *mut ctypes::sockaddr,
    addrlen: *mut ctypes::socklen_t,
) -> SyscallResult {
    unsafe { api::sys_getsockname(socket_fd, addr, addrlen) }.to_linux_result()
}
#[cfg(feature = "net")]
// Peer address query
#[inline]
pub unsafe fn sys_getpeername(
    socket_fd: c_int,
    addr: *mut ctypes::sockaddr,
    addrlen: *mut ctypes::socklen_t,
) -> SyscallResult {
    unsafe { api::sys_getpeername(socket_fd, addr, addrlen) }.to_linux_result()
}
