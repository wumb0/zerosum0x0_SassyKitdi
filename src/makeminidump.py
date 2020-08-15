#!/usr/bin/env python3

def makeminidump(where, major, minor, build, regions = [], modules = []):
	f = open(where, "wb")

	# MINIDUMP_HEADER
	f.write(b"MDMP")
	f.write(b"\x93\xa7")		# MDMP ver
	f.write(b"\x00\x00")		# Impl ver
	f.write(b"\x03\x00\x00\x00")	# 2 streams (sysinfo/modules/mem64)
	f.write(b"\x00\x01\x00\x00")	# RVA to dirs = 0x100
	f.write(b"\x00\x00\x00\x00")	# Checksum
	#f.write(b"\x00\x00\x00\x00")	# Reserved (union Timestamp?)
	f.write(b"\x00\x00\x00\x00")	# Timestamp
	f.write(b"\x02\x00\x00\x00")	# Flags = MiniDumpWithFullMemory

	f.seek(0x100)

	# MINIDUMP_DIRECTORY for sysinfo 
	f.write(b"\x07\x00\x00\x00")	# Type = SysInfo (7)
	f.write(b"\x00\x01\x00\x00")	# Size = 0x100 
	f.write(b"\x00\x02\x00\x00")	# RVA = 0x200

	# MINIDUMP_DIRECTORY for modules
	f.write(b"\x04\x00\x00\x00")	# Type = Modules (4)
	f.write(b"\x00\x10\x00\x00")	# Size = 0x1000
	f.write(b"\x00\x04\x00\x00")	# RVA = 0x400

	# MINIDUMP_DIRECTORY for MemoryList64
	f.write(b"\x09\x00\x00\x00")	# Type = Mem64 (9)
	f.write(b"\x00\x01\x00\x00")	# Size = 0x100
	f.write(b"\x00\x90\x00\x00")	# RVA = 0x9000

	f.seek(0x200)
	
	# MINIDUMP_SYSTEM_INFO 
	f.write(b"\x09\x00")		# ProcessorArch = 0x9 (AMD64)
	f.write(b"\x00\x00")		# ProcessorLevel = 0
	f.write(b"\x00\x00")		# ProcessorRevision = 0
	f.write(b"\x00\x00")		# Reserved
	#f.write(b"\x01\x00")		# NumProcessors = 1
	#f.write(b"\x02\x00")		# ProductType = Domain Controller
	f.write(major.to_bytes(4, "little"))
	f.write(minor.to_bytes(4, "little"))
	f.write(build.to_bytes(4, "little"))
	f.write(b"\x02\x00\x00\x00")	# PlatformId = NT	
	f.write(b"\x00\x03\x00\x00")	# CSDVersionRva = 0 (string of latest SP)
	f.write(b"\x00\x00\x00\x00")	# Reserved
	# CPU_INFORMATION will be 0s...	

	f.seek(0x300)
	f.write(b"\x00\x00\x00\x00") # CSDVersion 0 len

	f.seek(0x400)

	# MINIDUMP_MODULE_LIST
	f.write(len(modules).to_bytes(4, "little")) # NumberOfModules

	i = 0
	for module in modules:
		print(module)
		where = 0x404 + (i * 108) # sizeof(MINIDUMP_MODULE)
		f.seek(where)

		f.write(module[0].to_bytes(8, "little"))	# BaseAddr
		f.write(module[1].to_bytes(4, "little"))	# SizeOfImage
		f.write(b"\x00\x00\x00\x00")			# Checksum
		f.write(b"\x00\x00\x00\x00")			# TimeDateStamp
		
		module_name_rva = 0x5000 + (i * 100)
		f.write(module_name_rva.to_bytes(4, "little"))	# ModuleNameRVA
		f.write(b"\x00" * 13 * 4)			# VS_FIXEDFILEINFO
		f.write(b"\x00" * 2 * 4)			# CvRecord
		f.write(b"\x00" * 2 * 4)			# MiscRecord
		f.write(b"\x00" * 8 * 2)			# Reserved1 and Reserved2

		f.seek(module_name_rva)
		f.write(len(module[2]).to_bytes(4, "little"))	# Length
		f.write(module[2])	
		i += 1

	f.seek(0x9000)
	
	# MINIDUMP_MEMORY64_LIST
	f.write(len(regions).to_bytes(8, "little"))	# NumMemoryRegions
	f.write(b"\x00\x50\x01\x00\x00\x00\x00\x00")	# BaseRVA = 0x15000

	for region in regions:
		f.write(region[0].to_bytes(8, "little")) 	# VirtualAddress
		f.write(len(region[1]).to_bytes(8, "little")) 	# DataSize

	f.seek(0x15000)

	for region in regions:
		f.write(region[1])	# data

	f.close()

if __name__ == "__main__":
	modules = [(0xffdfc050, 1000, b"A\x00B\x00C\x00D\x00.\x00D\x00L\x00L\x00\x00")]
	regions = [(0xffdfc050, b"\xcc\xcd")]
	makeminidump(10, 0, 18363, regions, modules)
