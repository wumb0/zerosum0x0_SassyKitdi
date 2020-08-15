#![no_std]
#![feature(core_intrinsics)]

#[repr(C, packed)]
pub struct TdiFuncs {
    pub ex_allocate_pool: ntdef::functions::ExAllocatePool,
    pub ex_free_pool_with_tag: ntdef::functions::ExFreePoolWithTag,
    pub zw_create_file: ntdef::functions::ZwCreateFile,
    pub ob_reference_object_by_handle: ntdef::functions::ObReferenceObjectByHandle,
    pub io_allocate_mdl: ntdef::functions::IoAllocateMdl,
    //pub io_free_mdl: ntdef::functions::IoFreeMdl,
    pub io_build_device_io_control_request: ntdef::functions::IoBuildDeviceIoControlRequest,
    pub io_get_related_device_object: ntdef::functions::IoGetRelatedDeviceObject,
    pub iof_call_driver: ntdef::functions::IofCallDriver,
    pub ke_initialize_event: ntdef::functions::KeInitializeEvent,
    pub ke_wait_for_single_object: ntdef::functions::KeWaitForSingleObject,
    //pub mm_build_mdl_for_non_paged_pool: ntdef::functions::MmBuildMdlForNonPagedPool,
    pub mm_probe_and_lock_pages: ntdef::functions::MmProbeAndLockPages,
}

type TdiRecvHandler = unsafe fn(
    tdi_event_context:      ntdef::types::PVOID,
    connection_context:     ntdef::types::PVOID,
    receive_flags:          ntdef::types::ULONG,
    bytes_indicated:        ntdef::types::ULONG,
    bytes_available:        ntdef::types::ULONG,
    bytes_taken:            *mut ntdef::types::ULONG,
    buffer:                 ntdef::types::PVOID,
    irp:                    *mut ntdef::structs::PIRP,
) -> ntdef::types::NTSTATUS;

#[repr(C, packed)]
pub struct TdiContext {
    pub funcs:                          TdiFuncs,
    pub transport_handle:               ntdef::types::HANDLE,
    pub transport_file_object:          ntdef::structs::PFILE_OBJECT,
    pub connection_handle:              ntdef::types::HANDLE,
    pub connection_file_object:         ntdef::structs::PFILE_OBJECT,  
    pub recv_handler:                   TdiRecvHandler,  
}

pub struct TdiSocket {
    tdi_ctx:    *mut TdiContext,
}

pub trait Socket {
    fn new(tdi_ctx: *mut TdiContext) -> Self;
    unsafe fn add_recv_handler(&mut self, recv_handler: TdiRecvHandler);
    unsafe fn connect(&mut self, remote: u32, port: u16) -> Result<(), ntdef::types::NTSTATUS>;
    unsafe fn send(&mut self, buffer: *const u8, size: u32) -> Result<(), ntdef::types::NTSTATUS>;
}

impl Socket for TdiSocket {
    fn new(tdi_ctx: *mut TdiContext) -> Self {
        Self { tdi_ctx: tdi_ctx }
    }

    #[inline(always)]
    unsafe fn add_recv_handler(&mut self, handler: TdiRecvHandler) {
        (*self.tdi_ctx).recv_handler = handler;
    }

    /// connect
    /// 
    /// Creates a TDI transport and connection, associates them, adds the event 
    /// handlers, and connects to the target.
    /// 
    /// * `remote` - big-endian IPv4 Address
    /// * `port` - big-endian IP Port
    unsafe fn connect(
        &mut self, 
        remote: u32, 
        port: u16
    ) -> Result<(), ntdef::types::NTSTATUS> {

        self.tdi_open_transport()?;
        self.tdi_open_connection()?;

        let mut param: ntdef::structs::TDI_REQUEST_KERNEL_ASSOCIATE = core::mem::MaybeUninit::uninit().assume_init();
        param.AddressHandle = (*self.tdi_ctx).transport_handle;

        // Associate
        self.tdi_ioctl(
            (*self.tdi_ctx).connection_file_object,
            ntdef::enums::TDI_ASSOCIATE_ADDRESS,
            &mut param as *mut _ as _,
            core::mem::size_of_val(&param),
            ntdef::enums::NULL as _
        )?;

        // Set event handler
        if 0 as *mut u8 != core::mem::transmute((*self.tdi_ctx).recv_handler) 
        {

            let mut event_params: ntdef::structs::TDI_REQUEST_KERNEL_SET_EVENT = core::mem::MaybeUninit::uninit().assume_init();

            event_params.EventType = ntdef::enums::TDI_EVENT_RECEIVE as _;
            event_params.EventHandler = core::mem::transmute((*self.tdi_ctx).recv_handler);
            event_params.EventContext = self.tdi_ctx as _;

            self.tdi_ioctl(
                (*self.tdi_ctx).transport_file_object,
                ntdef::enums::TDI_SET_EVENT_HANDLER,
                &mut event_params as *mut _ as _,
                core::mem::size_of_val(&event_params),
                ntdef::enums::NULL as _
            )?;
        }

        let mut timeout: ntdef::structs::LARGE_INTEGER = core::mem::MaybeUninit::uninit().assume_init();
        let mut request_info: ntdef::structs::TDI_CONNECTION_INFORMATION = core::mem::MaybeUninit::uninit().assume_init();
        let mut return_info: ntdef::structs::TDI_CONNECTION_INFORMATION = core::mem::MaybeUninit::uninit().assume_init();
        //let mut buffer: [u8; 256] = core::mem::MaybeUninit::uninit().assume_init();
        let mut buffer: ntdef::structs::TRANSPORT_ADDRESS = core::mem::MaybeUninit::uninit().assume_init();
        let mut transport_address: ntdef::structs::PTRANSPORT_ADDRESS = &mut buffer; //buffer.as_mut_ptr() as _;
    
        // todo: do we need to zero all this or can we optimize this?
        ntdef::macros::RtlZeroMemory(&mut request_info as *mut _ as _, core::mem::size_of_val(&request_info));
        ntdef::macros::RtlZeroMemory(&mut return_info as *mut _ as _, core::mem::size_of_val(&return_info));
        ntdef::macros::RtlZeroMemory(transport_address as _, core::mem::size_of_val(&buffer));
    
        timeout.QuadPart = -(3i64 * 60 * 10000000) as _;  // 3 minutes  (negative 100ns)
    
        request_info.RemoteAddress = transport_address as _;
        request_info.RemoteAddressLength = 
            core::mem::size_of::<ntdef::structs::PTRANSPORT_ADDRESS>() as i32 +
            core::mem::size_of::<ntdef::structs::TDI_ADDRESS_IP>() as i32; 
    
        (*transport_address).TAAddressCount = 1;
        (*transport_address).Address[0].AddressType = ntdef::enums::TDI_ADDRESS_TYPE_IP;
        (*transport_address).Address[0].AddressLength = core::mem::size_of::<ntdef::structs::TDI_ADDRESS_IP>() as _;
        (*transport_address).Address[0].Address.sin_port = port;
        (*transport_address).Address[0].Address.in_addr = remote;
        
        let mut params: ntdef::structs::TDI_REQUEST_KERNEL = core::mem::MaybeUninit::uninit().assume_init();
        params.RequestConnectionInformation = &mut request_info;
        params.ReturnConnectionInformation = &mut return_info;
        params.RequestSpecific = &mut timeout as *mut _ as _;

        self.tdi_ioctl(
            (*self.tdi_ctx).connection_file_object,
            ntdef::enums::TDI_CONNECT,
            &mut params as *mut _ as _,
            core::mem::size_of_val(&params),
            ntdef::enums::NULL as _
        )?;

        Ok(())
    }

    unsafe fn send(
        &mut self,
        buffer: *const u8, 
        size: u32
    ) -> Result<(), ntdef::types::NTSTATUS> {
        let out = ((*self.tdi_ctx).funcs.ex_allocate_pool)(ntdef::enums::POOL_TYPE::NonPagedPool, size as _);
        ntdef::macros::RtlCopyMemory(out as _, buffer, size as _);

        let mdl = ((*self.tdi_ctx).funcs.io_allocate_mdl)(
            out,
            size as _,
            ntdef::enums::FALSE as _,
            ntdef::enums::FALSE as _,
            ntdef::enums::NULL as _,
        );

        // technically this should be wrapped in a SEH __try block, however we know the MDL buffer is good (and Rust no SEH)
        ((*self.tdi_ctx).funcs.mm_probe_and_lock_pages)(
            mdl,
            ntdef::enums::KPROCESSOR_MODE::KernelMode,
            ntdef::enums::LOCK_OPERATION::IoModifyAccess,
        );

        let mut param: ntdef::structs::TDI_REQUEST_KERNEL_SEND = core::mem::MaybeUninit::uninit().assume_init();

        param.SendFlags = 0;
        param.SendLength = size;

        self.tdi_ioctl(
            (*self.tdi_ctx).connection_file_object,
            ntdef::enums::TDI_SEND,
            &mut param as *mut _ as _,
            core::mem::size_of_val(&param),
            mdl
        )?;

        // IO manager should unlock and free the MDL
        //((*self.tdi_ctx).funcs.io_free_mdl)(mdl);

        ((*self.tdi_ctx).funcs.ex_free_pool_with_tag)(out, 0);

        Ok(())
    }
}

// Internal functions
impl TdiSocket {
    #[inline]
    unsafe fn tdi_open_transport(
        &mut self
    ) -> Result<(), ntdef::types::NTSTATUS>  {

        let mut fea_buffer: [u8; 1024] = 
            core::mem::MaybeUninit::uninit().assume_init();

        let mut transport_address: ntdef::structs::TRANSPORT_ADDRESS = 
            core::mem::MaybeUninit::uninit().assume_init();

        ntdef::macros::RtlZeroMemory(&mut transport_address as *mut _ as _, core::mem::size_of_val(&transport_address));

        transport_address.TAAddressCount = 1;
        transport_address.Address[0].AddressType = ntdef::enums::TDI_ADDRESS_TYPE_IP;
        transport_address.Address[0].AddressLength = core::mem::size_of::<ntdef::structs::TDI_ADDRESS_IP>() as _;
        //transport_address.Address[0].Address.sin_port = 0;   // any port
        //transport_address.Address[0].Address.in_host = 0x0;  // 0.0.0.0

        //let transport_ea_name = *b"TransportAddress";
        let transport_ea_name = [84u8, 114, 97, 110, 115, 112, 111, 114, 116, 65, 100, 100, 114, 101, 115, 115];

        ntdef::macros::make_single_fea(
            fea_buffer.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&fea_buffer),
            transport_ea_name.as_ptr(),
            core::mem::size_of_val(&transport_ea_name) as u8,
            &mut transport_address as *mut _ as *const _,
            core::mem::size_of_val(&transport_address) as u16,
        );

        let (handle, pfo) = self.tdi_open(
            fea_buffer.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&fea_buffer) as _,
        )?;

        (*self.tdi_ctx).transport_handle = handle;
        (*self.tdi_ctx).transport_file_object = pfo;

        Ok(())
    }

    #[inline]
    unsafe fn tdi_open_connection(
        &mut self
    ) -> Result<(), ntdef::types::NTSTATUS>  {
        let mut fea_buffer: [u8; 1024] = 
            core::mem::MaybeUninit::uninit().assume_init();

        //let connection_ea_name = *b"ConnectionContext";
        let connection_ea_name = [67u8, 111, 110, 110, 101, 99, 116, 105, 111, 110, 67, 111, 110, 116, 101, 120, 116];

        ntdef::macros::make_single_fea(
            fea_buffer.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&fea_buffer),
            connection_ea_name.as_ptr(),
            core::mem::size_of_val(&connection_ea_name) as u8,
            core::ptr::null(),
            core::mem::size_of::<usize>() as _,
        );


        let (handle, pfo) = self.tdi_open(
            fea_buffer.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&fea_buffer) as _,
        )?;

        (*self.tdi_ctx).connection_handle = handle;
        (*self.tdi_ctx).connection_file_object = pfo;        

        Ok(())
    }

    unsafe fn tdi_open(
        &self,
        fea: ntdef::types::PVOID, 
        fea_size: ntdef::types::ULONG
    ) -> Result<(ntdef::types::HANDLE, ntdef::structs::PFILE_OBJECT), ntdef::types::NTSTATUS> {

        let mut wsz_device_tcp = stacklstr::L!("\\Device\\Tcp");
        let mut us_device_tcp = ntstr::init_unicode_str!(wsz_device_tcp);
    
        let mut oa_tdi_name: ntdef::structs::OBJECT_ATTRIBUTES = core::mem::MaybeUninit::uninit().assume_init();
    
        ntdef::macros::InitializeObjectAttributes(
            &mut oa_tdi_name as _,
            &mut us_device_tcp as _,
            ntdef::enums::OBJ_CASE_INSENSITIVE | ntdef::enums::OBJ_KERNEL_HANDLE,
            core::ptr::null_mut(),
            core::ptr::null_mut()
        );
    
        let mut tdi_handle: ntdef::types::HANDLE = core::mem::MaybeUninit::uninit().assume_init();
        let mut io_status_block: ntdef::structs::IO_STATUS_BLOCK = core::mem::MaybeUninit::uninit().assume_init();
    
        let mut status = ((*self.tdi_ctx).funcs.zw_create_file)(
            &mut tdi_handle as _,
            ntdef::enums::GENERIC_READ | ntdef::enums::GENERIC_WRITE | ntdef::enums::SYNCHRONIZE,
            &mut oa_tdi_name as _,
            &mut io_status_block as _,
            core::ptr::null_mut(),
            ntdef::enums::FILE_ATTRIBUTE_NORMAL,
            ntdef::enums::FILE_SHARE_READ,
            ntdef::enums::FILE_OPEN_IF,
            0,
            fea,
            fea_size
        );
    
        let mut p_file_object: ntdef::structs::PFILE_OBJECT = core::mem::MaybeUninit::uninit().assume_init();
    
        if !ntdef::macros::NT_SUCCESS(status) {
            return Err(status)
        }
        
        status = ((*self.tdi_ctx).funcs.ob_reference_object_by_handle)(
            tdi_handle,
            ntdef::enums::GENERIC_READ | ntdef::enums::GENERIC_WRITE,
            core::ptr::null_mut(),
            ntdef::enums::KPROCESSOR_MODE::KernelMode,
            &mut p_file_object as _,
            core::ptr::null_mut()
        );
    
        if !ntdef::macros::NT_SUCCESS(status) {
            // ZwClose()
            return Err(status)
        }
        
    
        Ok((tdi_handle, p_file_object))
    }

    #[inline(never)]
    unsafe fn tdi_ioctl(
        &mut self,
        file_object:        ntdef::structs::PFILE_OBJECT,
        minor_function:     u8,
        parameters:         *mut u8,
        parameters_size:    usize,
        mdl:                ntdef::structs::PMDL,
    ) -> Result<(), ntdef::types::NTSTATUS> {
        let device_object = ((*self.tdi_ctx).funcs.io_get_related_device_object)(file_object);
        let mut tdi_completion_event: ntdef::structs::KEVENT = core::mem::MaybeUninit::uninit().assume_init();
        let mut io_status_block: ntdef::structs::IO_STATUS_BLOCK = core::mem::MaybeUninit::uninit().assume_init();


        let pirp = self.tdi_build_irp(
            &mut tdi_completion_event as _,
            device_object,
            &mut io_status_block,
        )?;

        let irpsp = TdiSocket::tdi_build_irpsp(
            pirp,
            device_object,
            file_object,
            core::ptr::null_mut(),  // CompletionRoutine
            core::ptr::null_mut(),  // Context
            minor_function
        );


        let p: *mut u8 = (*irpsp).Parameters.as_mut_ptr();

        ntdef::macros::RtlCopyMemory(p, parameters, parameters_size as _);

        if mdl != ntdef::enums::NULL {
            (*pirp).MdlAddress = mdl;
        }

        self.tdi_wait_irp(
            &mut tdi_completion_event as *mut _ as _,
            &mut io_status_block as _,
            device_object,
            pirp
        )?;

        Ok(())
    }

    unsafe fn tdi_build_irp(
        &mut self,
        tdi_completion_event:                   ntdef::structs::PKEVENT,
        device_object:                          ntdef::structs::PDEVICE_OBJECT,
        io_status_block:                        ntdef::structs::PIO_STATUS_BLOCK,
    ) -> Result<ntdef::structs::PIRP, ntdef::types::NTSTATUS> {

        ((*self.tdi_ctx).funcs.ke_initialize_event)(
            tdi_completion_event,
            ntdef::enums::EVENT_TYPE::NotificationEvent,
            ntdef::enums::FALSE as _
        );

        let pirp = ((*self.tdi_ctx).funcs.io_build_device_io_control_request)(
            0x00000003,
            device_object,
            ntdef::enums::NULL,
            0,
            ntdef::enums::NULL,
            0,
            ntdef::enums::TRUE as _,
            tdi_completion_event,
            io_status_block,
        );
    
        if pirp == ntdef::enums::NULL as _ {
            return Err(ntdef::enums::NTSTATUS::STATUS_INSUFFICIENT_RESOURCES as _);
        }
    
        Ok(pirp)
    }

    unsafe fn tdi_build_irpsp(
        irp:                    ntdef::structs::PIRP,
        device_object:          ntdef::structs::PDEVICE_OBJECT,
        file_object:            ntdef::structs::PFILE_OBJECT,
        completion_routine:     ntdef::types::PVOID,
        context:                ntdef::types::PVOID,
        minor_function:          u8
    ) -> ntdef::structs::PIO_STACK_LOCATION {
        if completion_routine != ntdef::enums::NULL {
            ntdef::macros::IoSetCompletionRoutine(
                irp, 
                completion_routine, 
                context, 
                ntdef::enums::TRUE as _, 
                ntdef::enums::TRUE as _, 
                ntdef::enums::TRUE as _
            );
        }
        else {
            ntdef::macros::IoSetCompletionRoutine(
                irp, 
                ntdef::enums::NULL as _,
                ntdef::enums::NULL as _, 
                ntdef::enums::FALSE as _, 
                ntdef::enums::FALSE as _, 
                ntdef::enums::FALSE as _
            );
        }
    
        let irpsp = ntdef::macros::IoGetNextIrpStackLocation(irp);
        (*irpsp).MajorFunction = ntdef::enums::IRP_MJ_INTERNAL_DEVICE_CONTROL;
        (*irpsp).MinorFunction = minor_function; 
        (*irpsp).DeviceObject = device_object;
        (*irpsp).FileObject = file_object;
    
        irpsp
    }

    unsafe fn tdi_wait_irp(
        &mut self,
        tdi_completion_event:                   ntdef::structs::PKEVENT,
        io_status_block:                        ntdef::structs::PIO_STATUS_BLOCK,
        device_object:                          ntdef::structs::PDEVICE_OBJECT,
        pirp:                                   ntdef::structs::PIRP,
    ) -> Result<(), ntdef::types::NTSTATUS> {
        
        let mut status = ((*self.tdi_ctx).funcs.iof_call_driver)(device_object, pirp);
    
        if status == ntdef::enums::NTSTATUS::STATUS_PENDING as _ {
            ((*self.tdi_ctx).funcs.ke_wait_for_single_object)(
                tdi_completion_event as _,
                ntdef::enums::KWAIT_REASON::Executive,
                ntdef::enums::KPROCESSOR_MODE::KernelMode,
                ntdef::enums::FALSE as _,
                ntdef::enums::NULL as _
            );
        }    
    
        status = (*io_status_block).Status;
        
        if ntdef::macros::NT_SUCCESS(status) {
            return Ok(());
        }
    
        Err(status)
    }
    
}