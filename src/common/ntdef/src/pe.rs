#[repr(C, packed)]
pub struct IMAGE_DOS_HEADER {
	pub e_magic: u16,
	pub e_cblp: u16,
	pub e_cp: u16,
	pub e_crlc: u16,
	pub e_cparhdr: u16,
	pub e_minalloc: u16,
	pub e_maxalloc: u16,
	pub e_ss: u16,
	pub e_sp: u16,
	pub e_csum: u16,
	pub e_ip: u16,
	pub e_cs: u16,
	pub e_lfarlc: u16,
	pub e_ovno: u16,
	pub e_res: [u16; 4],
	pub e_oemid: u16,
	pub e_oeminfo: u16,
	pub e_res2: [u16; 10],
	pub e_lfanew: u32,
}

pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;

#[repr(C, packed)]
pub struct IMAGE_FILE_HEADER {
    pub     Machine:                u16,
    pub     NumberOfSections:       u16,
    pub     TimeDateStamp:          u32,
    pub     PointerToSymbolTable:   u32,
    pub     NumberOfSymbols:        u32,
    pub     SizeOfOptionalHeader:   u16,
    pub     Characteristics:        u16,
}

pub type PIMAGE_FILE_HEADER = *mut IMAGE_FILE_HEADER;

pub enum IMAGE_DIRECTORY_ENTRY {
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0,
	IMAGE_DIRECTORY_ENTRY_IMPORT,
	IMAGE_DIRECTORY_ENTRY_RESOURCE,
	IMAGE_DIRECTORY_ENTRY_EXCEPTION,
	IMAGE_DIRECTORY_ENTRY_SECURITY,
	IMAGE_DIRECTORY_ENTRY_BASERELOC,
	IMAGE_DIRECTORY_ENTRY_DEBUG,
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
	IMAGE_DIRECTORY_ENTRY_TLS,
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
	IMAGE_DIRECTORY_ENTRY_IAT,
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
}

const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C, packed)]
pub struct IMAGE_DATA_DIRECTORY {
	pub     VirtualAddress: u32,
	pub     Size: u32,
}

pub type PIMAGE_DATA_DIRECTORY = *mut IMAGE_DATA_DIRECTORY;

#[repr(C, packed)]
pub struct IMAGE_OPTIONAL_HEADER64 {
	pub     Magic:	u16,
	pub     MajorLinkerVersion: u8,
	pub     MinorLinkerVersion: u8,
	pub     SizeOfCode: u32,
	pub     SizeofInitializedData: u32,
	pub     SizeofUninitializedData: u32,
	pub     AddressOfEntryPoint: u32,
	pub		BaseOfCode: u32,
	pub     ImageBase: u64,
	pub     SectionAlignment: u32,
	pub     FileAlignment: u32,
	pub     MajorOperatingSystemVersion: u16,
	pub     MinorOperatingSystemVersion: u16,
	pub		MajorImageVersion: u16,
	pub		MinorImageVersion: u16,
	pub     MajorSubsystemVersion: u16,
	pub     MinorSubsystemVersion: u16,
	pub     Win32VersionValue: u32,
	pub     SizeOfImage: u32,
	pub     SizeOfHeaders: u32,
	pub     CheckSum: u32,
	pub     Subsystem: u16,
	pub     DllCharacteristics: u16,
	pub     SizeOfStackReserver: u64,
	pub     SizeOfStackCommit: u64,
	pub     SizeOfHeapReserve: u64,
	pub     SizeOfHeapCommit: u64,
	pub     LoaderFlags: u32,
	pub     NumberOfRvaAndSizes: u32,
	pub     DataDirectory:	[IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

pub type PIMAGE_OPTIONAL_HEADER64 = *mut IMAGE_OPTIONAL_HEADER64;

#[repr(C, packed)]
pub struct IMAGE_NT_HEADERS64 {
    pub     Signature:  u32,
    pub     FileHeader: IMAGE_FILE_HEADER,
    pub     OptionalHeader: IMAGE_OPTIONAL_HEADER64
}

pub type PIMAGE_NT_HEADERS64 = *mut IMAGE_NT_HEADERS64;

#[repr(C, packed)]
pub struct IMAGE_EXPORT_DIRECTORY {
	pub	Characteristics: u32,
	pub TimeDateStamp: u32,
	pub MajorVersion: u16,
	pub MinorVersion: u16,
	pub Name: u32,
	pub Base: u32,
	pub NumberOfFunctions: u32,
	pub NumberOfNames: u32,
	pub AddressOfFunctions: u32,
	pub AddressOfNames: u32,
	pub AddressOfNameOrdinals: u32,
}

pub type PIMAGE_EXPORT_DIRECTORY = *mut IMAGE_EXPORT_DIRECTORY;
