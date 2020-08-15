// todo: make these structs?
pub type PFILE_OBJECT = crate::types::PVOID;
pub type PDEVICE_OBJECT = crate::types::PVOID;
pub type PMDL = crate::types::PVOID;
pub type PEPROCESS = crate::types::PVOID;
pub type PRKPROCESS = crate::types::PVOID;
pub type PKPROCESS = crate::types::PVOID;

#[repr(C)]
pub struct UNICODE_STRING {
    pub     Length:         crate::types::USHORT,
    pub     MaximumLength:  crate::types::USHORT,
    pub     Buffer:         crate::types::PWSTR,
}

pub type PUNICODE_STRING = *mut UNICODE_STRING;

#[repr(C, packed)]
pub struct LARGE_INTEGER {
    pub QuadPart: crate::types::UINT64,
    //pub     LowPart:        crate::types::DWORD,
    //pub     HighPart:       crate::types::DWORD,
}

pub type PLARGE_INTEGER = *mut LARGE_INTEGER;

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub     Status:         crate::types::NTSTATUS,   // union: Pointer: crate::types::PVOID,
    pub     Information:    crate::types::PVOID,
}

pub type PIO_STATUS_BLOCK = *mut IO_STATUS_BLOCK;

/*
1: kd> dt nt!_OBJECT_ATTRIBUTES
   +0x000 Length           : Uint4B
   +0x008 RootDirectory    : Ptr64 Void
   +0x010 ObjectName       : Ptr64 _UNICODE_STRING
   +0x018 Attributes       : Uint4B
   +0x020 SecurityDescriptor : Ptr64 Void
   +0x028 SecurityQualityOfService : Ptr64 Void
*/
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub     Length:                     crate::types::ULONG,
    pub     RootDirectory:              crate::types::HANDLE,
    pub     ObjectName:                 crate::structs::PUNICODE_STRING,
    pub     Attributes:                 crate::types::ULONG,
    pub     SecurityDescriptor:         crate::types::PVOID,
    pub     SecurityQualityOfService:   crate::types::PVOID,
}


pub type POBJECT_ATTRIBUTES = *mut OBJECT_ATTRIBUTES;

#[repr(C, packed)]
pub struct LIST_ENTRY {
    pub Flink:  crate::types::PVOID,
    pub Blink:  crate::types::PVOID,
}

#[repr(C, packed)]
pub struct KEVENT {
    pub Lock:           crate::types::LONG,
    pub SignalState:    crate::types::LONG,
    pub WaitListHead:   crate::structs::LIST_ENTRY,
}

pub type PKEVENT = *mut KEVENT;

// TDI
#[repr(C, packed)]
pub struct TDI_REQUEST_KERNEL_ASSOCIATE { 
    pub AddressHandle:  crate::types::HANDLE,
}

pub type PTDI_REQUEST_KERNEL_ASSOCIATE = *mut TDI_REQUEST_KERNEL_ASSOCIATE;

#[repr(C)]
pub struct TDI_REQUEST_KERNEL_SET_EVENT {
    pub EventType:      crate::types::LONG,
    pub EventHandler:   crate::types::PVOID,
    pub EventContext:   crate::types::PVOID,
}

pub type PTDI_REQUEST_KERNEL_SET_EVENT = *mut TDI_REQUEST_KERNEL_SET_EVENT;

#[repr(C)]
pub struct TDI_CONNECTION_INFORMATION {
    pub UserDataLength:         crate::types::LONG,
    pub UserData:               crate::types::PVOID,
    pub OptionsLength:          crate::types::LONG,
    pub Options:                crate::types::PVOID,
    pub RemoteAddressLength:    crate::types::LONG,
    pub RemoteAddress:          crate::types::PVOID,
}

pub type PTDI_CONNECTION_INFORMATION = *mut TDI_CONNECTION_INFORMATION;

#[repr(C)]
pub struct TDI_REQUEST_KERNEL {
    pub RequestFlags:                       crate::types::ULONG_PTR,
    pub RequestConnectionInformation:       crate::structs::PTDI_CONNECTION_INFORMATION,
    pub ReturnConnectionInformation:        crate::structs::PTDI_CONNECTION_INFORMATION,
    pub RequestSpecific:                    crate::types::PVOID,
}

pub type PTDI_REQUEST_KERNEL = *mut TDI_REQUEST_KERNEL;

#[repr(C, packed)]
pub struct TDI_REQUEST_KERNEL_SEND {
    pub SendLength: crate::types::ULONG,
    pub SendFlags: crate::types::ULONG,
}

pub type PTDI_REQUEST_KERNEL_SEND = *mut TDI_REQUEST_KERNEL_SEND;

#[cfg(target_arch="x86_64")]
#[repr(C, packed)]
pub struct IRP {
    pub Type: crate::types::USHORT,
    pub Size: crate::types::USHORT,
    pub Padding_0x4_0x8:  [u8; 4],
    pub MdlAddress: crate::structs::PMDL,
    // and more...
}

pub type PIRP = *mut crate::structs::IRP;

#[cfg(target_arch="x86_64")]
#[repr(C, packed)]
pub struct IO_STACK_LOCATION {
    pub MajorFunction:      crate::types::UCHAR,
    pub MinorFunction:      crate::types::UCHAR,
    pub Flags:              crate::types::UCHAR,
    pub Control:            crate::types::UCHAR,
    pub Padding_0x4_0x8:    [u8; 0x4],
    pub Parameters:         [crate::types::BYTE; 0x20],
    pub DeviceObject:       crate::structs::PDEVICE_OBJECT,
    pub FileObject:         crate::structs::PFILE_OBJECT,
    pub CompletionRoutine:  crate::types::PVOID,
    pub Context:            crate::types::PVOID,
}

pub type PIO_STACK_LOCATION = *mut IO_STACK_LOCATION;

#[repr(C, packed)]
pub struct FILE_FULL_EA_INFORMATION {
    pub NextEntryOffset:        crate::types::ULONG,
    pub Flags:                  crate::types::UCHAR,
    pub EaNameLength:           crate::types::UCHAR,
    pub EaValueLength:          crate::types::USHORT,
    // pub EaName: [u8; 1],
} 

pub type PFILE_FULL_EA_INFORMATION = *mut FILE_FULL_EA_INFORMATION;


#[repr(C, packed)]
pub struct TDI_ADDRESS_IP {
    pub sin_port:   crate::types::USHORT,
    pub in_addr:    crate::types::ULONG,
    pub sin_zero:   [crate::types::UCHAR; 8],
}

pub type PTDI_ADDRESS_IP = *mut TDI_ADDRESS_IP;

#[repr(C, packed)]
pub struct TA_ADDRESS {
    pub AddressLength:  crate::types::USHORT,
    pub AddressType:    crate::types::USHORT,
    pub Address:        crate::structs::TDI_ADDRESS_IP,
}

pub type PTA_ADDRESS = *mut TA_ADDRESS;

#[repr(C, packed)]
pub struct TRANSPORT_ADDRESS {
    pub TAAddressCount:     crate::types::LONG,
    pub Address:            [crate::structs::TA_ADDRESS; 1],
}

pub type PTRANSPORT_ADDRESS = *mut TRANSPORT_ADDRESS;

#[repr(C)]
pub struct KAPC_STATE {
    pub ApcListHead:            [crate::structs::LIST_ENTRY; 2],
    pub Process:                crate::structs::PRKPROCESS,
    pub KernelApcInProgress:    crate::types::UCHAR,
    pub KernelApcPending:       crate::types::UCHAR,
    pub UserApcPending:         crate::types::UCHAR,
}

pub type PKAPC_STATE = *mut KAPC_STATE;

#[repr(C)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress:            crate::types::PVOID,
    pub AllocationBase:         crate::types::PVOID,
    pub AllocationProtect:      crate::types::ULONG,
    pub PartitionId:            crate::types::USHORT,
    pub RegionSize:             crate::types::SIZE_T,
    pub State:                  crate::types::ULONG,
    pub Protect:                crate::types::ULONG,
    pub Type:                   crate::types::ULONG,
}

#[repr(C)]
pub struct RTL_OSVERSIONINFOW {
    pub dwOSVersionInfoSize:        crate::types::ULONG,
    pub dwMajorVersion:             crate::types::ULONG,
    pub dwMinorVersion:             crate::types::ULONG,
    pub dwBuildNumber:              crate::types::ULONG,
    pub dwPlatformId:               crate::types::ULONG,
    pub szCSDVersion:               [crate::types::UINT16; 128],    
}

pub type PRTL_OSVERSIONINFOW = *mut RTL_OSVERSIONINFOW;

#[cfg(target_arch="x86_64")]
#[repr(C, packed)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks:               crate::structs::LIST_ENTRY,
    pub InMemoryOrderLinks:             crate::structs::LIST_ENTRY,
    pub InInitializationOrderLinks:     crate::structs::LIST_ENTRY,
    pub DllBase:                        crate::types::PVOID,
    pub EntryPoint:                     crate::types::PVOID,
    pub SizeOfImage:                    crate::types::ULONG,
    pub Padding_0x44_0x48:              [crate::types::BYTE; 4],
    pub FullDllName:                    crate::structs::UNICODE_STRING,
    pub BaseDllName:                    crate::structs::UNICODE_STRING,
    /* ...etc... */
}

pub type PLDR_DATA_TABLE_ENTRY = *mut LDR_DATA_TABLE_ENTRY;

#[repr(C, packed)]
pub struct PEB_LDR_DATA {
    pub Length:                     crate::types::ULONG,
    pub Initialized:                crate::types::ULONG,
    pub SsHandle:                   crate::types::PVOID,
    pub InLoadOrderModuleList:      crate::structs::LIST_ENTRY,
    /* ...etc... */
}

pub type PPEB_LDR_DATA = *mut PEB_LDR_DATA;

#[repr(C, packed)]
pub struct PEB {
    pub InheritedAddressSpace:      crate::types::BOOLEAN,
    pub ReadImageFileExecOptions:   crate::types::BOOLEAN,
    pub BeingDebugged:              crate::types::BOOLEAN,
    pub SpareBool:                  crate::types::BOOLEAN,
    pub Padding_0x4_0x8:            [crate::types::BYTE; 4],
    pub Mutant:                     crate::types::HANDLE,
    pub ImageBaseAddress:           crate::types::PVOID,
    pub Ldr:                        crate::structs::PPEB_LDR_DATA,
    /* ...etc... */
}

pub type PPEB = *mut PEB;

#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION { 
    pub Reserved1:          crate::types::PVOID,
    pub PebBaseAddress:     crate::structs::PPEB,
    pub Reserved2:          [crate::types::PVOID; 2],
    pub UniqueProcessId:    crate::types::ULONG_PTR,
    pub Reserved3:          crate::types::PVOID,
}