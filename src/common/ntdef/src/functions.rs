pub type ExAllocatePool = extern "stdcall" fn(
    pool_type:  crate::enums::POOL_TYPE,
    size:       crate::types::SIZE_T,
) -> crate::types::PVOID;

pub type ExFreePoolWithTag = extern "stdcall" fn(
    Buffer:     crate::types::PVOID,
    Tag:        crate::types::ULONG,
) -> ();

pub type ZwCreateFile = extern "stdcall" fn(
    FileHandle:         crate::types::PHANDLE,
    AccessMask:         crate::types::ACCESS_MASK,
    ObjectAttributes:   crate::structs::POBJECT_ATTRIBUTES,
    IoStatusBlock:      crate::structs::PIO_STATUS_BLOCK,
    AllocationSize:     crate::structs::PLARGE_INTEGER,
    FileAttributes:     crate::types::ULONG,
    ShareAccess:        crate::types::ULONG,
    CreateDisposition:  crate::types::ULONG,
    CreateOptions:      crate::types::ULONG,
    EaBuffer:           crate::types::PVOID,
    EaLength:           crate::types::ULONG,
) -> crate::types::NTSTATUS;

pub type ObReferenceObjectByHandle = extern "stdcall" fn(
    Handle:             crate::types::HANDLE,
    AccessMask:         crate::types::ACCESS_MASK,
    ObjectType:         crate::types::PVOID, // POBJECT_TYPE,
    AccessMode:         crate::enums::KPROCESSOR_MODE,
    Object:             *mut crate::types::PVOID, // PVOID*,
    HandleInformation:  crate::types::PVOID, // POBJECT_HANDLE_INFORMATION,
) -> crate::types::NTSTATUS;

pub type IoBuildDeviceIoControlRequest = extern "stdcall" fn(
    IoControlCode:              crate::types::ULONG,
    DeviceObject:               crate::structs::PDEVICE_OBJECT,
    InputBuffer:                crate::types::PVOID,
    InputBufferLength:          crate::types::ULONG,
    OutputBuffer:               crate::types::PVOID,
    OutputBufferLength:         crate::types::ULONG,
    InternalDeviceIoControl:    crate::types::BOOLEAN,
    Event:                      crate::structs::PKEVENT,
    IoStatusBlock:              crate::structs::PIO_STATUS_BLOCK,
) -> crate::structs::PIRP;

pub type IoGetRelatedDeviceObject = extern "stdcall" fn(
    FileObject: crate::structs::PFILE_OBJECT,
) -> crate::structs::PDEVICE_OBJECT;

pub type IofCallDriver = extern "fastcall" fn(
    DeviceObject:   crate::structs::PDEVICE_OBJECT,
    Irp:            crate::structs::PIRP,
) -> crate::types::NTSTATUS;

pub type KeInitializeEvent = extern "stdcall" fn(
    Event:      crate::structs::PKEVENT,
    Type:       crate::enums::EVENT_TYPE,
    State:      crate::types::BOOLEAN,
) -> ();

pub type KeWaitForSingleObject = extern "stdcall" fn(
    Object:         crate::types::PVOID,
    WaitReason:     crate::enums::KWAIT_REASON,
    WaitMode:       crate::enums::KPROCESSOR_MODE,
    Alertable:      crate::types::BOOLEAN,
    Timeout:        crate::structs::PLARGE_INTEGER,
) -> ();

pub type IoAllocateMdl = extern "stdcall" fn(
    VirtualAddress:     crate::types::PVOID,
    Length:             crate::types::ULONG,
    SecondaryBuffer:    crate::types::BOOLEAN,
    ChargeQuote:        crate::types::BOOLEAN,
    Irp:                crate::structs::PIRP,
) -> crate::structs::PMDL;

pub type IoFreeMdl = extern "stdcall" fn(
    Mdl:    crate::structs::PMDL,
) -> ();

pub type MmBuildMdlForNonPagedPool = extern "stdcall" fn(
    Mdl:    crate::structs::PMDL,
) -> ();

pub type MmProbeAndLockPages = extern "stdcall" fn(
    Mdl:        crate::structs::PMDL,
    AccessMove: crate::enums::KPROCESSOR_MODE,
    Operation:  crate::enums::LOCK_OPERATION,
) -> ();

pub type MmSecureVirtualMemory = extern "stdcall" fn(
    Address:        crate::types::PVOID,
    Size:           crate::types::SIZE_T,
    ProbeMode:      crate::types::ULONG,
) -> crate::types::HANDLE;


pub type MmUnsecureVirtualMemory = extern "stdcall" fn(
    SecureHandle:        crate::types::HANDLE,
) -> ();

pub type PsGetProcessImageFileName = extern "stdcall" fn(
    process:    crate::structs::PEPROCESS,
) -> crate::types::PCHAR;

pub type PsLookupProcessByProcessId  = extern "stdcall" fn(
    ProcessId:      crate::types::HANDLE,
    Process:        *mut crate::structs::PEPROCESS,
) -> crate::types::NTSTATUS;

pub type ObfDereferenceObject = extern "fastcall" fn(
    Object:     crate::types::PVOID,
) -> crate::types::ULONG_PTR;

pub type KeStackAttachProcess = extern "stdcall" fn(
    Process:     crate::structs::PRKPROCESS,
    ApcState:    crate::structs::PKAPC_STATE,
) -> ();

pub type KeUnstackDetachProcess = extern "stdcall" fn(
    ApcState:   crate::structs::PKAPC_STATE,
) -> ();

pub type ZwQueryVirtualMemory = extern "stdcall" fn(
    ProcessHandle:              crate::types::HANDLE,
    BaseAddress:                crate::types::PVOID,
    MemoryInformationClass:     crate::enums::MEMORY_INFORMATION_CLASS,
    MemoryInformation:          crate::types::PVOID,
    MemoryInformationLength:    crate::types::SIZE_T,
    ReturnLength:               crate::types::PSIZE_T,
) -> crate::types::NTSTATUS;

pub type RtlGetVersion = extern "stdcall" fn(
    lpVersionInformation: crate::structs::PRTL_OSVERSIONINFOW,
) -> crate::types::NTSTATUS;

pub type ZwQueryInformationProcess = extern "stdcall" fn(
    ProcessHandle:  crate::types::HANDLE,
    ProcessInformationClass:    crate::enums::PROCESSINFOCLASS,
    ProcessInformation:         crate::types::PVOID,
    ProcessInformationLength:   crate::types::ULONG,
    ReturnLength:               crate::types::PULONG,
) -> crate::types::NTSTATUS;