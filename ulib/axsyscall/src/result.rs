use core::ffi::c_long;

use axerrno::{AxError, LinuxError, LinuxResult};

pub type SyscallResult = LinuxResult<isize>;

pub trait LinuxResultToIsize {
    fn as_isize(self) -> isize;
}

impl LinuxResultToIsize for SyscallResult {
    fn as_isize(self) -> isize {
        match self {
            Ok(val) => val,
            Err(e) => -e.code() as isize,
        }
    }
}

// 自定义转换 trait 绕过孤儿规则
pub trait ToLinuxResult {
    fn to_linux_result(self) -> SyscallResult;
}

impl ToLinuxResult for i32 {
    fn to_linux_result(self) -> SyscallResult {
        if self >= 0 {
            Ok(self as isize)
        } else {
            let code = (-self) as i32;
            Err(LinuxError::try_from(code).unwrap_or(LinuxError::EINVAL))
        }
    }
}

impl ToLinuxResult for isize {
    fn to_linux_result(self) -> SyscallResult {
        if self >= 0 {
            Ok(self)
        } else {
            let code = match i32::try_from(-self) {
                Ok(c) => c,
                Err(_) => return Err(LinuxError::EOVERFLOW),
            };
            Err(LinuxError::try_from(code).unwrap_or(LinuxError::EINVAL))
        }
    }
}

//impl<T: Into<isize> + TryInto<i32> + PartialOrd<Rhs = isize> + core::ops::Neg<Output = TryInto<i32>>> ToLinuxResult for T {
//fn to_linux_result(self) -> SyscallResult {
//if self >= 0 {
/*
 *let code = match isize::try_from(self) {
 *    Ok(c) => c,
 *    Err(_) => return Err(LinuxError::EOVERFLOW),
 *};
 */
//Ok(code as isize)
//} else {
//let code = match i32::try_from(-self) {
//Ok(c) => c,
//Err(_) => return Err(LinuxError::EOVERFLOW),
//};
//Err(LinuxError::try_from(code).unwrap_or(LinuxError::EINVAL))
//}
//}
//}

impl ToLinuxResult for usize {
    fn to_linux_result(self) -> SyscallResult {
        Ok(self as isize)
    }
}
impl ToLinuxResult for c_long {
    fn to_linux_result(self) -> SyscallResult {
        Ok(self as isize)
    }
}

/*
 *impl<T: Into<isize>> ToLinuxResult for T {
 *    fn to_linux_result(self) -> SyscallResult {
 *        Ok(self.into())
 *    }
 *}
 */
