//! Defines types and probe methods of all supported devices.

#![allow(unused_imports, dead_code)]

use crate::AxDeviceEnum;
use axdriver_base::DeviceType;

#[cfg(feature = "virtio")]
use crate::virtio::{self, VirtIoDevMeta};

#[cfg(feature = "bus-pci")]
use axdriver_pci::{DeviceFunction, DeviceFunctionInfo, PciRoot};

pub use super::dummy::*;

pub trait DriverProbe {
    fn probe_global() -> Option<AxDeviceEnum> {
        None
    }

    #[cfg(bus = "mmio")]
    fn probe_mmio(_mmio_base: usize, _mmio_size: usize) -> Option<AxDeviceEnum> {
        None
    }

    #[cfg(bus = "pci")]
    fn probe_pci(
        _root: &mut PciRoot,
        _bdf: DeviceFunction,
        _dev_info: &DeviceFunctionInfo,
    ) -> Option<AxDeviceEnum> {
        None
    }
}

#[cfg(net_dev = "virtio-net")]
register_net_driver!(
    <virtio::VirtIoNet as VirtIoDevMeta>::Driver,
    <virtio::VirtIoNet as VirtIoDevMeta>::Device
);

#[cfg(block_dev = "virtio-blk")]
register_block_driver!(
    <virtio::VirtIoBlk as VirtIoDevMeta>::Driver,
    <virtio::VirtIoBlk as VirtIoDevMeta>::Device
);

#[cfg(display_dev = "virtio-gpu")]
register_display_driver!(
    <virtio::VirtIoGpu as VirtIoDevMeta>::Driver,
    <virtio::VirtIoGpu as VirtIoDevMeta>::Device
);

cfg_if::cfg_if! {
    if #[cfg(block_dev = "ramdisk")] {
        pub struct RamDiskDriver;
        register_block_driver!(RamDiskDriver, axdriver_block::ramdisk::RamDisk);

        impl DriverProbe for RamDiskDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                // TODO: format RAM disk
                Some(AxDeviceEnum::from_block(
                    axdriver_block::ramdisk::RamDisk::new(0x100_0000), // 16 MiB
                ))
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "bcm2835-sdhci")]{
        pub struct BcmSdhciDriver;
        register_block_driver!(MmckDriver, axdriver_block::bcm2835sdhci::SDHCIDriver);

        impl DriverProbe for BcmSdhciDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                debug!("mmc probe");
                axdriver_block::bcm2835sdhci::SDHCIDriver::try_new().ok().map(AxDeviceEnum::from_block)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "dw-mshc")]{
        pub struct DwMshcDriver;
        register_block_driver!(MmckDriver, axdriver_block::dw_mshc::DwMshcDriver);

        impl DriverProbe for DwMshcDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                debug!("mmc probe dw-mshc");

                axfdt::FDT.get()
                    .or_else(|| {
                        warn!("FDT not initialized or available.");
                        None // 如果 FDT 不可用，则整个过程返回 None
                    })
                    .and_then(|device_tree| {
                        device_tree.find_node("/soc/mmc@16020000") // Option<Node>
                    })
                    .or_else(|| {
                        warn!("cannot find mmc");
                        None
                    })
                    .and_then(|sdhci_node| {
                        let mut reg_iter = sdhci_node.reg()?;

                        let reg_entry = reg_iter.next()?;

                        let base_address = reg_entry.starting_address as usize;
                        let size = reg_entry.size?;

                        let irq_number = 33; // Hard-coded from JH7110

                        info!("SD Card Host Controller found at 0x{:x}", base_address);

                        Some(AxDeviceEnum::from_block(
                            axdriver_block::dw_mshc::DwMshcDriver::new(base_address, size, irq_number)
                        ))
                    })
                /*
                 *if let Some(device_tree) = axfdt::FDT.get() {
                 *    // Parse SD Card Host Controller
                 *    if let Some(sdhci) = device_tree.find_node("/soc/mmc@16020000") {
                 *        let base_address = sdhci.reg().unwrap().next().unwrap().starting_address as usize;
                 *        let size = sdhci.reg().unwrap().next().unwrap().size.unwrap();
                 *        let irq_number = 33; // Hard-coded from JH7110
                 *        info!("SD Card Host Controller found at 0x{:x}", base_address);
                 *        return Some(AxDeviceEnum::from_block(
                 *            axdriver_block::dw_mshc::DwMshcDriver::new(base_address,size,irq_number)
                 *        ));
                 *    }
                 *}
                 */
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(net_dev = "ixgbe")] {
        use crate::ixgbe::IxgbeHalImpl;
        use axhal::mem::phys_to_virt;
        pub struct IxgbeDriver;
        register_net_driver!(IxgbeDriver, axdriver_net::ixgbe::IxgbeNic<IxgbeHalImpl, 1024, 1>);
        impl DriverProbe for IxgbeDriver {
            #[cfg(bus = "pci")]
            fn probe_pci(
                    root: &mut axdriver_pci::PciRoot,
                    bdf: axdriver_pci::DeviceFunction,
                    dev_info: &axdriver_pci::DeviceFunctionInfo,
                ) -> Option<crate::AxDeviceEnum> {
                    use axdriver_net::ixgbe::{INTEL_82599, INTEL_VEND, IxgbeNic};
                    if dev_info.vendor_id == INTEL_VEND && dev_info.device_id == INTEL_82599 {
                        // Intel 10Gb Network
                        info!("ixgbe PCI device found at {:?}", bdf);

                        // Initialize the device
                        // These can be changed according to the requirments specified in the ixgbe init function.
                        const QN: u16 = 1;
                        const QS: usize = 1024;
                        let bar_info = root.bar_info(bdf, 0).unwrap();
                        match bar_info {
                            axdriver_pci::BarInfo::Memory {
                                address,
                                size,
                                ..
                            } => {
                                let ixgbe_nic = IxgbeNic::<IxgbeHalImpl, QS, QN>::init(
                                    phys_to_virt((address as usize).into()).into(),
                                    size as usize
                                )
                                .expect("failed to initialize ixgbe device");
                                return Some(AxDeviceEnum::from_net(ixgbe_nic));
                            }
                            axdriver_pci::BarInfo::IO { .. } => {
                                error!("ixgbe: BAR0 is of I/O type");
                                return None;
                            }
                        }
                    }
                    None
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(net_dev = "fxmac")]{
        use axalloc::global_allocator;
        use axhal::mem::PAGE_SIZE_4K;

        #[crate_interface::impl_interface]
        impl axdriver_net::fxmac::KernelFunc for FXmacDriver {
            fn virt_to_phys(addr: usize) -> usize {
                axhal::mem::virt_to_phys(addr.into()).into()
            }

            fn phys_to_virt(addr: usize) -> usize {
                axhal::mem::phys_to_virt(addr.into()).into()
            }

            fn dma_alloc_coherent(pages: usize) -> (usize, usize) {
                let Ok(vaddr) = global_allocator().alloc_pages(pages, PAGE_SIZE_4K) else {
                    error!("failed to alloc pages");
                    return (0, 0);
                };
                let paddr = axhal::mem::virt_to_phys((vaddr).into());
                debug!("alloc pages @ vaddr={:#x}, paddr={:#x}", vaddr, paddr);
                (vaddr, paddr.as_usize())
            }

            fn dma_free_coherent(vaddr: usize, pages: usize) {
                global_allocator().dealloc_pages(vaddr, pages);
            }

            fn dma_request_irq(_irq: usize, _handler: fn()) {
                warn!("unimplemented dma_request_irq for fxmax");
            }
        }

        register_net_driver!(FXmacDriver, axdriver_net::fxmac::FXmacNic);

        pub struct FXmacDriver;
        impl DriverProbe for FXmacDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                info!("fxmac for phytiumpi probe global");
                axdriver_net::fxmac::FXmacNic::init(0).ok().map(AxDeviceEnum::from_net)
            }
        }
    }
}
