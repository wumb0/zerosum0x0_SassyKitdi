#![no_std]
#![feature(asm)]

pub mod hash;

pub unsafe fn get_proc<T, X, R>(
    base_addr: ntdef::types::PVOID, 
    hash: u32) 
-> Result<extern "stdcall" fn(T, X) -> R, ntdef::types::NTSTATUS> {
    core::mem::transmute(get_proc_address(base_addr, hash))
}

pub unsafe fn get_proc_address(
    base_addr: ntdef::types::PVOID, 
    hash: u32
) -> Result<ntdef::types::PVOID, ntdef::types::NTSTATUS> {
    const EXPORT_ENTRY: usize = ntdef::pe::IMAGE_DIRECTORY_ENTRY::IMAGE_DIRECTORY_ENTRY_EXPORT as _;

    let base_addr: *mut u8 = base_addr as _;

    let dos_header: ntdef::pe::PIMAGE_DOS_HEADER = base_addr as _;
    let nt_header: ntdef::pe::PIMAGE_NT_HEADERS64 = base_addr.offset((*dos_header).e_lfanew as _) as _;
    let data_dir: ntdef::pe::PIMAGE_DATA_DIRECTORY = 
        &mut (*nt_header).OptionalHeader.DataDirectory[EXPORT_ENTRY] as _;

    let export_dir: ntdef::pe::PIMAGE_EXPORT_DIRECTORY = base_addr.offset((*data_dir).VirtualAddress as _) as _;
    let names: *mut u32 = base_addr.offset((*export_dir).AddressOfNames as _) as _;
    let ordinals: *mut u16 = base_addr.offset((*export_dir).AddressOfNameOrdinals as _) as _;
    let functions: *mut u32 = base_addr.offset((*export_dir).AddressOfFunctions as _) as _;

    for i in 0..(*export_dir).NumberOfNames {
        let sz_name = base_addr.offset(*names.offset(i as _) as _);

        let name_hash = crate::hash::fnv1a_32_hash(sz_name as _, true, false);

        if name_hash == hash {
            return Ok(base_addr.offset(*functions.offset(*ordinals.offset(i as _ ) as _) as _) as _);
        }
    }
    
    Err(ntdef::enums::NTSTATUS::STATUS_NOT_FOUND as _)
}

#[inline]
pub fn find_nt_base_address() -> ntdef::types::PVOID {
    let mut idt_entry = unsafe { get_kpcr_idt_base_entry() } as usize;

    idt_entry &= !(0xfff as usize) as usize;

    loop {
        let check_mz: *const u16 = idt_entry as _;

        if unsafe { *check_mz == 0x5a4d } {
            break;
        }

        idt_entry -= 0x1000;
    }

    idt_entry as _
}

#[inline]
#[cfg(target_arch = "x86_64")]
unsafe fn get_kpcr_idt_base_entry() -> ntdef::types::PVOID {
    let result: ntdef::types::PVOID;

    /*
    llvm_asm!(
       "
            mov rax, qword ptr gs:0x38           #  KPCR.IdtBase
            mov rax, qword ptr [rax + 0x4]       #  IdtBase->KIDTENTRY64
       "
       : "={rax}"(result)               // output operands
       :                                // input operands
       :                                // clobbers
       : "intel", "volatile"            // options
    );
    */

    asm!(
        "mov {0}, qword ptr gs:0x38",       //  KPCR.IdtBase
        "mov {0}, qword ptr [{0} + 0x4]",   //  IdtBase->KIDTENTRY64
        out(reg) result,
    );

    result
}
