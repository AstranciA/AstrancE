pub const SYSINFO: SysInfo = SysInfo {
    sysname: axconfig::SYSNAME,
    nodename: axconfig::NODENAME,
    release: axconfig::RELEASE,
    version: axconfig::VERSION,
    machine: axconfig::ARCH,
    logo: axconfig::LOGO,
};

#[derive(Debug)]
pub struct SysInfo {
    pub sysname: &'static str,
    pub nodename: &'static str,
    pub release: &'static str,
    pub version: &'static str,
    pub machine: &'static str,
    pub logo: &'static str,
}

impl Default for SysInfo {
    fn default() -> Self {
        Self {
            sysname: axconfig::SYSNAME,
            nodename: Default::default(),
            release: Default::default(),
            version: Default::default(),
            machine: Default::default(),
            logo: Default::default(),
        }
    }
}
