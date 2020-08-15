#![no_std]
#![feature(core_intrinsics)]

#[repr(C, packed)]
pub struct MemDumpFuncs {
    pub ke_stack_attach_process:            ntdef::functions::KeStackAttachProcess,
    pub ke_unstack_detach_process:          ntdef::functions::KeUnstackDetachProcess,
    pub mm_secure_virtual_memory:           ntdef::functions::MmSecureVirtualMemory,
    pub mm_unsecure_virtual_memory:         ntdef::functions::MmUnsecureVirtualMemory,
    pub obf_dereference_object:             ntdef::functions::ObfDereferenceObject,
    pub ps_get_process_image_file_name:     ntdef::functions::PsGetProcessImageFileName,
    pub ps_lookup_process_by_process_id:    ntdef::functions::PsLookupProcessByProcessId,
    pub zw_query_information_process:       ntdef::functions::ZwQueryInformationProcess,
    pub zw_query_virtual_memory:            ntdef::functions::ZwQueryVirtualMemory,
}

pub struct MemoryDumper {
    funcs:                  *const MemDumpFuncs,
    process:                ntdef::structs::PEPROCESS,
    current_address:        usize,
    secure_handle:          ntdef::types::HANDLE,
    apc_state:              ntdef::structs::KAPC_STATE,
    first_flink:            ntdef::types::PVOID,
    current_flink:          ntdef::types::PVOID,
}

impl Drop for MemoryDumper {
    fn drop(&mut self) {
        unsafe {
            ((*self.funcs).ke_unstack_detach_process)(&mut self.apc_state as _);
            ((*self.funcs).obf_dereference_object)(self.process);
        }
    }
}

impl MemoryDumper {
    pub fn new(funcs: *const MemDumpFuncs, process_name_hash: u32) -> Result<Self, ntdef::types::NTSTATUS> {
        unsafe {
            let mut pid: u32 = 0x0;
            
            loop {
                pid += 4;

                let mut process: ntdef::structs::PEPROCESS = core::ptr::null_mut();
                let status = ((*funcs).ps_lookup_process_by_process_id)(pid as _, &mut process as _);

                if !ntdef::macros::NT_SUCCESS(status) {
                    continue;
                }
                
                let proc_name = ((*funcs).ps_get_process_image_file_name)(process);

                if resolver::hash::fnv1a_32_hash(proc_name, true, false) == process_name_hash {

                    let mut ret = Self { 
                        funcs: funcs, 
                        process: process, 
                        current_address: 0,
                        secure_handle: ntdef::enums::NULL,
                        apc_state: core::mem::MaybeUninit::uninit().assume_init(),
                        first_flink: ntdef::enums::NULL,
                        current_flink: ntdef::enums::NULL,
                    };

                    ((*funcs).ke_stack_attach_process)(process, &mut ret.apc_state as _);
                    return Ok(ret);
                }

                ((*funcs).obf_dereference_object)(process);

                if pid >= 0xffff {
                    break;
                }
            }

            Err(ntdef::enums::NTSTATUS::STATUS_NOT_FOUND as _)
        }
    }

    pub unsafe fn next_range(
        &mut self
    ) -> Result<(ntdef::types::PVOID, ntdef::types::SIZE_T), ntdef::types::NTSTATUS> {
        
        if self.secure_handle != ntdef::enums::NULL {
            ((*self.funcs).mm_unsecure_virtual_memory)(self.secure_handle);
            self.secure_handle = ntdef::enums::NULL;
        }


        loop {
            let mut meminfo: ntdef::structs::MEMORY_BASIC_INFORMATION = core::mem::MaybeUninit::uninit().assume_init();
            let mut return_length: ntdef::types::SIZE_T = 0;

            let status = ((*self.funcs).zw_query_virtual_memory)(
                -1 as _, // "Current Process" handle (under KeStackAttachProcess)
                self.current_address as _,
                ntdef::enums::MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
                &mut meminfo as *mut _ as _,
                core::mem::size_of_val(&meminfo),
                &mut return_length,
            );

            if !ntdef::macros::NT_SUCCESS(status) || return_length == 0 {
                return Err(status);
            }

            self.current_address = meminfo.BaseAddress as usize + meminfo.RegionSize;

            if meminfo.State != ntdef::enums::MEM_COMMIT {
                continue;
            }

            self.secure_handle = ((*self.funcs).mm_secure_virtual_memory)(
                meminfo.BaseAddress,
                meminfo.RegionSize,
                ntdef::enums::PAGE_READONLY,
            );

            if self.secure_handle != ntdef::enums::NULL {
                return Ok((meminfo.BaseAddress, meminfo.RegionSize))
            }
        }
    }

    pub unsafe fn next_module(
        &mut self
    ) -> Result<(ntdef::types::PVOID, u32, ntdef::types::PVOID), ntdef::types::NTSTATUS> {

        //core::intrinsics::breakpoint();
        
        if self.first_flink == ntdef::enums::NULL {
            let mut basic_info: ntdef::structs::PROCESS_BASIC_INFORMATION = core::mem::MaybeUninit::uninit().assume_init();
            let mut return_length: ntdef::types::ULONG = 0;

            let status = ((*self.funcs).zw_query_information_process)(
                -1 as _,
                ntdef::enums::PROCESSINFOCLASS::ProcessBasicInformation,
                &mut basic_info as *mut _ as _,
                core::mem::size_of_val(&basic_info) as _,
                &mut return_length as _,
            );

            if !ntdef::macros::NT_SUCCESS(status) {
                return Err(status);
            }

            self.first_flink = (*(*(basic_info.PebBaseAddress)).Ldr).InLoadOrderModuleList.Flink;
            self.current_flink = (*(*(basic_info.PebBaseAddress)).Ldr).InLoadOrderModuleList.Flink;
        }

        let ldr_data_entry: ntdef::structs::PLDR_DATA_TABLE_ENTRY = self.current_flink as _;
        self.current_flink = (*ldr_data_entry).InLoadOrderLinks.Flink;

        let ldr_data_entry: ntdef::structs::PLDR_DATA_TABLE_ENTRY = self.current_flink as _;

        if self.current_flink == self.first_flink || (*ldr_data_entry).BaseDllName.Buffer == ntdef::enums::NULL as _ {
            return Err(ntdef::enums::NTSTATUS::STATUS_NO_MORE_ENTRIES as _);
        }

        Ok(((*ldr_data_entry).DllBase, (*ldr_data_entry).SizeOfImage, (*ldr_data_entry).BaseDllName.Buffer as _))
    }
}