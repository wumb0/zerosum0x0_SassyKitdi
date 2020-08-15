pub const TRUE: u32 = 1;
pub const FALSE: u32 = 0;

pub const NULL: crate::types::PVOID = core::ptr::null_mut();

pub const FILE_READ_EA: u32 = 0x8;
pub const FILE_WRITE_EA: u32 = 0x10;

pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

pub const FILE_OPEN_IF: u32 = 0x3;

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const GENERIC_ALL: u32 = 0x10000000;

pub const SYNCHRONIZE: u32 = 0x00100000;

pub const FILE_SHARE_READ: u32 = 0x1;

pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
pub const OBJ_KERNEL_HANDLE: u32 = 0x00000200;

pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;

// CPU modes
#[repr(i32)]
pub enum KPROCESSOR_MODE {
    KernelMode = 0,
    UserMode = 1,
}

#[repr(i32)]
pub enum LOCK_OPERATION {
    IoReadAccess = 0,
    IoWriteAccess = 1,
    IoModifyAccess = 2,
}

// Pools
#[repr(i32)]
pub enum POOL_TYPE {
    NonPagedPool = 0,
    PagedPool = 1,
    NonPagedPoolNx = 512,
}

#[repr(i32)]
pub enum EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
}

#[repr(i32)]
pub enum KWAIT_REASON {
    Executive = 0,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrSpare0,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    MaximumWaitReason
}

pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0f;

// TDI
pub const TDI_ASSOCIATE_ADDRESS: u8 = 0x1;
pub const TDI_DISASSOCIATE_ADDRESS: u8 = 0x2;
pub const TDI_CONNECT: u8 = 0x3;
pub const TDI_LISTEN: u8 = 0x4;
pub const TDI_ACCEPT: u8 = 0x5;
pub const TDI_DISCONNECT: u8 = 0x6;
pub const TDI_SEND: u8 = 0x7;
pub const TDI_RECEIVE: u8 = 0x8;
pub const TDI_SEND_DATAGRAM: u8 = 0x9;
pub const TDI_RECEIVE_DATAGRAM: u8 = 0xa;
pub const TDI_SET_EVENT_HANDLER: u8 = 0xb;
pub const TDI_QUERY_INFORMATION: u8 = 0xc;
pub const TDI_SET_INFORMATION: u8 = 0xd;
pub const TDI_ACTION: u8 = 0xe;

pub const TDI_DIRECT_SEND: u8 = 0x27;
pub const TDI_DIRECT_SEND_DATAGRAM: u8 = 0x29;
pub const TDI_DIRECT_ACCEPT: u8 = 0x2a;

pub const TDI_ADDRESS_TYPE_IP: u16 = 2;

pub const TDI_EVENT_CONNECT: u16 = 0;
pub const TDI_EVENT_DISCONNECT: u16 = 1;
pub const TDI_EVENT_ERROR: u16 = 2;
pub const TDI_EVENT_RECEIVE: u16 = 3;
pub const TDI_EVENT_RECEIVE_DATAGRAM: u16 = 4;
pub const TDI_EVENT_RECEIVE_EXPEDITED: u16 = 5;
pub const TDI_EVENT_SEND_POSSIBLE: u16 = 6;

#[allow(overflowing_literals)]
#[repr(i32)]
pub enum NTSTATUS {
    STATUS_SUCCESS = 0,
    STATUS_PENDING = 0x00000103,

    STATUS_NO_MORE_ENTRIES = 0x8000001A,

    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A,
    STATUS_NOT_FOUND = 0xC0000225,

    STATUS_NOT_LOCKED = 0xC000002A,
}

#[repr(i32)]
pub enum MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
}

#[repr(i32)]
pub enum PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29,
    ProcessSubsystemInformation = 75,
}

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;

pub const MEM_COMMIT: u32 = 0x00001000;