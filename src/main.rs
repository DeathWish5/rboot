//! Simple ELF OS Loader on UEFI
//!
//! 1. Load config from "\EFI\Boot\rboot.conf"
//! 2. Load kernel ELF file
//! 3. Map ELF segments to virtual memory
//! 4. Map kernel stack and all physical memory
//! 5. Exit boot and jump to ELF entry

#![no_std]
#![no_main]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate log;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::asm;
use rboot::BootInfo;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::*;
use uefi::table::cfg::{ACPI2_GUID, SMBIOS_GUID};
use uefi::{prelude::*, CStr16};
use x86_64::registers::control::*;
use x86_64::structures::paging::*;
use x86_64::{PhysAddr, VirtAddr};
use xmas_elf::ElfFile;

use uefi::proto::{
    device_path::DevicePath,
    loaded_image::LoadedImage,
    media::file::{File, FileAttribute, FileInfo, FileMode, FileType, RegularFile},
    ProtocolPointer,
};

mod config;
mod page_table;

const CONFIG_PATH: &str = "\\EFI\\Boot\\rboot.conf";

#[entry]
fn efi_main(image: uefi::Handle, mut st: SystemTable<Boot>) -> Status {
    // Initialize utilities (logging, memory allocation...)
    uefi_services::init(&mut st).expect("failed to initialize utilities");
    let bs = st.boot_services();

    info!("bootloader is running");

    let config = {
        let mut file = open_file(image, &st, CONFIG_PATH);
        let buf = load_file(bs, &mut file);
        config::Config::parse(buf)
    };
    info!("config: {:#x?}", config);

    let elf = {
        let mut file = open_file(image, &st, config.kernel_path);
        let buf = load_file(bs, &mut file);
        ElfFile::new(buf).expect("failed to parse ELF")
    };
    unsafe {
        ENTRY = elf.header.pt2.entry_point() as usize;
    }

    info!("config: {:#x?}", config);

    let acpi2_addr = st
        .config_table()
        .iter()
        .find(|entry| entry.guid == ACPI2_GUID)
        .expect("failed to find ACPI 2 RSDP")
        .address;
    info!("acpi2: {:?}", acpi2_addr);

    let smbios_addr = st
        .config_table()
        .iter()
        .find(|entry| entry.guid == SMBIOS_GUID)
        .expect("failed to find SMBIOS")
        .address;
    info!("smbios: {:?}", smbios_addr);

    let (initramfs_addr, initramfs_size) = if let Some(path) = config.initramfs {
        let mut file = open_file(image, &st, path);
        let buf = load_file(bs, &mut file);
        (buf.as_ptr() as u64, buf.len() as u64)
    } else {
        (0, 0)
    };

    let max_mmap_size = st.boot_services().memory_map_size().map_size;
    let mmap_storage = Box::leak(vec![0; max_mmap_size * 2].into_boxed_slice());
    let mmap_iter = st.boot_services().memory_map(mmap_storage).unwrap();
    let max_phys_addr = mmap_iter
        .entries()
        .map(|m| m.phys_start + m.page_count * 0x1000)
        .max()
        .unwrap()
        .max(0x1_0000_0000); // include IOAPIC MMIO area

    let mut page_table = current_page_table();
    // root page table is readonly
    // disable write protect
    unsafe {
        Cr0::update(|f| f.remove(Cr0Flags::WRITE_PROTECT));
        Efer::update(|f| f.insert(EferFlags::NO_EXECUTE_ENABLE));
    }
    page_table::map_elf(&elf, &mut page_table, &mut UEFIFrameAllocator(bs))
        .expect("failed to map ELF");
    page_table::map_stack(
        config.kernel_stack_address,
        config.kernel_stack_size,
        &mut page_table,
        &mut UEFIFrameAllocator(bs),
    )
    .expect("failed to map stack");
    page_table::map_physical_memory(
        config.physical_memory_offset,
        max_phys_addr,
        &mut page_table,
        &mut UEFIFrameAllocator(bs),
    );
    // recover write protect
    unsafe {
        Cr0::update(|f| f.insert(Cr0Flags::WRITE_PROTECT));
    }

    info!("exit boot services");

    let mut memory_map = Vec::with_capacity(128);

    let (_rt, mmap_iter) = st.exit_boot_services();
    // NOTE: alloc & log can no longer be used

    for desc in mmap_iter.entries() {
        memory_map.push(*desc);
    }

    // construct BootInfo
    let bootinfo = BootInfo {
        memory_map,
        physical_memory_offset: config.physical_memory_offset,
        // graphic_info,
        acpi2_rsdp_addr: acpi2_addr as u64,
        smbios_addr: smbios_addr as u64,
        initramfs_addr,
        initramfs_size,
        cmdline: config.cmdline,
    };
    let stacktop = config.kernel_stack_address + config.kernel_stack_size * 0x1000;
    unsafe {
        jump_to_entry(&bootinfo, stacktop);
    }
}

/// Get current page table from CR3
fn current_page_table() -> OffsetPageTable<'static> {
    let p4_table_addr = Cr3::read().0.start_address().as_u64();
    let p4_table = unsafe { &mut *(p4_table_addr as *mut PageTable) };
    unsafe { OffsetPageTable::new(p4_table, VirtAddr::new(0)) }
}

/// Use `BootServices::allocate_pages()` as frame allocator
struct UEFIFrameAllocator<'a>(&'a BootServices);

unsafe impl FrameAllocator<Size4KiB> for UEFIFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let addr = self
            .0
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("failed to allocate frame");
        let frame = PhysFrame::containing_address(PhysAddr::new(addr));
        Some(frame)
    }
}

/// Jump to ELF entry according to global variable `ENTRY`
unsafe fn jump_to_entry(bootinfo: *const BootInfo, stacktop: u64) -> ! {
    asm!("mov rsp, {}; call {}", in(reg) stacktop, in(reg) ENTRY, in("rdi") bootinfo);
    loop {
        asm!("nop");
    }
}

/// The entry point of kernel, set by BSP.
static mut ENTRY: usize = 0;

fn open_device_path_protocol(
    image: Handle,
    st: &SystemTable<Boot>,
) -> Option<ScopedProtocol<DevicePath>> {
    let this = st.boot_services();
    let loaded_image = unsafe {
        this.open_protocol::<LoadedImage>(
            OpenProtocolParams {
                handle: image,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    };

    if loaded_image.is_err() {
        log::error!("Failed to open protocol LoadedImage");
        return None;
    }
    let loaded_image = loaded_image.unwrap();
    let loaded_image = &*loaded_image;

    let device_handle = loaded_image.device();

    let device_path = unsafe {
        this.open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle: device_handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    };
    if device_path.is_err() {
        log::error!("Failed to open protocol DevicePath");
        return None;
    }
    Some(device_path.unwrap())
}

fn locate_and_open_protocol<P: ProtocolPointer>(
    image: Handle,
    st: &SystemTable<Boot>,
) -> Option<ScopedProtocol<P>> {
    let this = st.boot_services();
    let device_path = open_device_path_protocol(image, st)?;
    let mut device_path = &*device_path;

    let fs_handle = this.locate_device_path::<P>(&mut device_path);
    if fs_handle.is_err() {
        log::error!("Failed to open device path");
        return None;
    }

    let fs_handle = fs_handle.unwrap();

    let opened_handle = unsafe {
        this.open_protocol::<P>(
            OpenProtocolParams {
                handle: fs_handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    };

    if opened_handle.is_err() {
        log::error!("Failed to open protocol {}", core::any::type_name::<P>());
        return None;
    }
    Some(opened_handle.unwrap())
}

/// Open file at `path`
pub fn open_file(image_handle: uefi::Handle, st: &SystemTable<Boot>, path: &str) -> RegularFile {
    info!("opening file: {}", path);
    let mut fs_raw = locate_and_open_protocol::<SimpleFileSystem>(image_handle, st)
        .expect("failed to open file system");
    let fs = &mut *fs_raw;

    let mut buf = [0u16; 256];
    let path = CStr16::from_str_with_buf(path, &mut buf).expect("failed to convert path to ucs-2");
    let mut root = fs.open_volume().expect("failed to open volume");
    let handle = root
        .open(path, FileMode::Read, FileAttribute::empty())
        .expect("failed to open file");

    match handle.into_type().expect("failed to into_type") {
        FileType::Regular(regular) => regular,
        _ => panic!("Invalid file type"),
    }
}

/// Load file to new allocated pages
pub fn load_file(bs: &BootServices, file: &mut RegularFile) -> &'static mut [u8] {
    info!("loading file to memory");
    let mut info_buf = [0u8; 0x100];
    let info = file
        .get_info::<FileInfo>(&mut info_buf)
        .expect("failed to get file info");
    let pages = info.file_size() as usize / 0x1000 + 1;
    let mem_start = bs
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .expect("failed to allocate pages");
    let buf = unsafe { core::slice::from_raw_parts_mut(mem_start as *mut u8, pages * 0x1000) };
    let len = file.read(buf).expect("failed to read file");
    &mut buf[..len]
}
