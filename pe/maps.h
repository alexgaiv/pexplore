#ifndef _MAPS_H_
#define _MAPS_H_

#include <Windows.h>
#include <winnt.h>

struct IntStr {
	int id;
	const char *str;
};

IntStr signature[] = {
	5, "",
	IMAGE_DOS_SIGNATURE, "IMAGE_DOS_SIGNATURE",
	IMAGE_OS2_SIGNATURE, "IMAGE_OS2_SIGNATURE",
	IMAGE_OS2_SIGNATURE_LE, "IMAGE_OS2_SIGNATURE_LE",
	IMAGE_VXD_SIGNATURE, "IMAGE_VXD_SIGNATURE",
	IMAGE_NT_SIGNATURE, "IMAGE_NT_SIGNATURE"
};

IntStr machine[] = {
	30, "",
	IMAGE_FILE_MACHINE_UNKNOWN, "IMAGE_FILE_MACHINE_UNKNOWN",
	IMAGE_FILE_MACHINE_I386, "IMAGE_FILE_MACHINE_I386",
	IMAGE_FILE_MACHINE_R3000, "IMAGE_FILE_MACHINE_R3000",
	IMAGE_FILE_MACHINE_R4000, "IMAGE_FILE_MACHINE_R4000",
	IMAGE_FILE_MACHINE_R10000, "IMAGE_FILE_MACHINE_R10000",
	IMAGE_FILE_MACHINE_WCEMIPSV2, "IMAGE_FILE_MACHINE_WCEMIPSV2",
	IMAGE_FILE_MACHINE_ALPHA, "IMAGE_FILE_MACHINE_ALPHA",
	IMAGE_FILE_MACHINE_SH3, "IMAGE_FILE_MACHINE_SH3",
	IMAGE_FILE_MACHINE_SH3DSP, "IMAGE_FILE_MACHINE_SH3DSP",
	IMAGE_FILE_MACHINE_SH3E, "IMAGE_FILE_MACHINE_SH3E",
	IMAGE_FILE_MACHINE_SH4, "IMAGE_FILE_MACHINE_SH4",
	IMAGE_FILE_MACHINE_SH5, "IMAGE_FILE_MACHINE_SH5",
	IMAGE_FILE_MACHINE_ARM, "IMAGE_FILE_MACHINE_ARM",
	IMAGE_FILE_MACHINE_THUMB, "IMAGE_FILE_MACHINE_THUMB",
	IMAGE_FILE_MACHINE_ARMNT, "IMAGE_FILE_MACHINE_ARMNT",
	IMAGE_FILE_MACHINE_AM33, "IMAGE_FILE_MACHINE_AM33",
	IMAGE_FILE_MACHINE_POWERPC, "IMAGE_FILE_MACHINE_POWERPC",
	IMAGE_FILE_MACHINE_POWERPCFP, "IMAGE_FILE_MACHINE_POWERPCFP",
	IMAGE_FILE_MACHINE_IA64, "IMAGE_FILE_MACHINE_IA64",
	IMAGE_FILE_MACHINE_MIPS16, "IMAGE_FILE_MACHINE_MIPS16",
	IMAGE_FILE_MACHINE_ALPHA64, "IMAGE_FILE_MACHINE_ALPHA64",
	IMAGE_FILE_MACHINE_MIPSFPU, "IMAGE_FILE_MACHINE_MIPSFPU",
	IMAGE_FILE_MACHINE_MIPSFPU16, "IMAGE_FILE_MACHINE_MIPSFPU16",
	IMAGE_FILE_MACHINE_AXP64, "IMAGE_FILE_MACHINE_AXP64",
	IMAGE_FILE_MACHINE_TRICORE, "IMAGE_FILE_MACHINE_TRICORE",
	IMAGE_FILE_MACHINE_CEF, "IMAGE_FILE_MACHINE_CEF",
	IMAGE_FILE_MACHINE_EBC, "IMAGE_FILE_MACHINE_EBC",
	IMAGE_FILE_MACHINE_AMD64, "IMAGE_FILE_MACHINE_AMD64",
	IMAGE_FILE_MACHINE_M32R, "IMAGE_FILE_MACHINE_M32R",
	IMAGE_FILE_MACHINE_CEE, "IMAGE_FILE_MACHINE_CEE",
};

IntStr characteristics[] = {
	15, "",
	IMAGE_FILE_RELOCS_STRIPPED, "IMAGE_FILE_RELOCS_STRIPPED",
	IMAGE_FILE_EXECUTABLE_IMAGE, "IMAGE_FILE_EXECUTABLE_IMAGE",
	IMAGE_FILE_LINE_NUMS_STRIPPED, "IMAGE_FILE_LINE_NUMS_STRIPPED",
	IMAGE_FILE_LOCAL_SYMS_STRIPPED, "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
	IMAGE_FILE_AGGRESIVE_WS_TRIM, "IMAGE_FILE_AGGRESIVE_WS_TRIM",
	IMAGE_FILE_LARGE_ADDRESS_AWARE, "IMAGE_FILE_LARGE_ADDRESS_AWARE",
	IMAGE_FILE_BYTES_REVERSED_LO, "IMAGE_FILE_BYTES_REVERSED_LO",
	IMAGE_FILE_32BIT_MACHINE, "IMAGE_FILE_32BIT_MACHINE",
	IMAGE_FILE_DEBUG_STRIPPED, "IMAGE_FILE_DEBUG_STRIPPED",
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
	IMAGE_FILE_NET_RUN_FROM_SWAP, "IMAGE_FILE_NET_RUN_FROM_SWAP",
	IMAGE_FILE_SYSTEM, "IMAGE_FILE_SYSTEM",
	IMAGE_FILE_DLL, "IMAGE_FILE_DLL",
	IMAGE_FILE_UP_SYSTEM_ONLY, "IMAGE_FILE_UP_SYSTEM_ONLY",
	IMAGE_FILE_BYTES_REVERSED_HI, "IMAGE_FILE_BYTES_REVERSED_HI",
};

IntStr ntsignature[] = {
	3, "",
	IMAGE_NT_OPTIONAL_HDR32_MAGIC, "IMAGE_NT_OPTIONAL_HDR32_MAGIC",
	IMAGE_NT_OPTIONAL_HDR64_MAGIC, "IMAGE_NT_OPTIONAL_HDR64_MAGIC",
	IMAGE_ROM_OPTIONAL_HDR_MAGIC, "IMAGE_ROM_OPTIONAL_HDR_MAGIC",
};

IntStr subsystem[] = {
	14, "",
	IMAGE_SUBSYSTEM_UNKNOWN, "IMAGE_SUBSYSTEM_UNKNOWN",
	IMAGE_SUBSYSTEM_NATIVE, "IMAGE_SUBSYSTEM_NATIVE",
	IMAGE_SUBSYSTEM_WINDOWS_GUI, "IMAGE_SUBSYSTEM_WINDOWS_GUI",
	IMAGE_SUBSYSTEM_WINDOWS_CUI, "IMAGE_SUBSYSTEM_WINDOWS_CUI",
	IMAGE_SUBSYSTEM_OS2_CUI, "IMAGE_SUBSYSTEM_OS2_CUI",
	IMAGE_SUBSYSTEM_POSIX_CUI, "IMAGE_SUBSYSTEM_POSIX_CUI",
	IMAGE_SUBSYSTEM_NATIVE_WINDOWS, "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
	IMAGE_SUBSYSTEM_EFI_APPLICATION, "IMAGE_SUBSYSTEM_EFI_APPLICATION",
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
	IMAGE_SUBSYSTEM_EFI_ROM, "IMAGE_SUBSYSTEM_EFI_ROM",
	IMAGE_SUBSYSTEM_XBOX, "IMAGE_SUBSYSTEM_XBOX",
	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
};

IntStr dllcharacteristics[] = {
	10, "",
	IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
	IMAGE_DLLCHARACTERISTICS_NO_SEH, "IMAGE_DLLCHARACTERISTICS_NO_SEH",
	IMAGE_DLLCHARACTERISTICS_NO_BIND, "IMAGE_DLLCHARACTERISTICS_NO_BIND",
	IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
};

IntStr scncharacteristics[] = {
	47, "",
	IMAGE_SCN_TYPE_NO_PAD, "IMAGE_SCN_TYPE_NO_PAD",
	IMAGE_SCN_CNT_CODE, "IMAGE_SCN_CNT_CODE",
	IMAGE_SCN_CNT_INITIALIZED_DATA, "IMAGE_SCN_CNT_INITIALIZED_DATA",
	IMAGE_SCN_CNT_UNINITIALIZED_DATA, "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
	IMAGE_SCN_LNK_OTHER, "IMAGE_SCN_LNK_OTHER",
	IMAGE_SCN_LNK_INFO, "IMAGE_SCN_LNK_INFO",
	IMAGE_SCN_LNK_REMOVE, "IMAGE_SCN_LNK_REMOVE",
	IMAGE_SCN_LNK_COMDAT, "IMAGE_SCN_LNK_COMDAT",
	IMAGE_SCN_NO_DEFER_SPEC_EXC, "IMAGE_SCN_NO_DEFER_SPEC_EXC",
	IMAGE_SCN_GPREL, "IMAGE_SCN_GPREL",
	IMAGE_SCN_MEM_FARDATA, "IMAGE_SCN_MEM_FARDATA",
	IMAGE_SCN_MEM_PURGEABLE, "IMAGE_SCN_MEM_PURGEABLE",
	IMAGE_SCN_MEM_16BIT, "IMAGE_SCN_MEM_16BIT",
	IMAGE_SCN_MEM_LOCKED, "IMAGE_SCN_MEM_LOCKED",
	IMAGE_SCN_MEM_PRELOAD, "IMAGE_SCN_MEM_PRELOAD",
	IMAGE_SCN_ALIGN_1BYTES, "IMAGE_SCN_ALIGN_1BYTES",
	IMAGE_SCN_ALIGN_2BYTES, "IMAGE_SCN_ALIGN_2BYTES",
	IMAGE_SCN_ALIGN_4BYTES, "IMAGE_SCN_ALIGN_4BYTES",
	IMAGE_SCN_ALIGN_8BYTES, "IMAGE_SCN_ALIGN_8BYTES",
	IMAGE_SCN_ALIGN_16BYTES, "IMAGE_SCN_ALIGN_16BYTES",
	IMAGE_SCN_ALIGN_32BYTES, "IMAGE_SCN_ALIGN_32BYTES",
	IMAGE_SCN_ALIGN_64BYTES, "IMAGE_SCN_ALIGN_64BYTES",
	IMAGE_SCN_ALIGN_128BYTES, "IMAGE_SCN_ALIGN_128BYTES",
	IMAGE_SCN_ALIGN_256BYTES, "IMAGE_SCN_ALIGN_256BYTES",
	IMAGE_SCN_ALIGN_512BYTES, "IMAGE_SCN_ALIGN_512BYTES",
	IMAGE_SCN_ALIGN_1024BYTES, "IMAGE_SCN_ALIGN_1024BYTES",
	IMAGE_SCN_ALIGN_2048BYTES, "IMAGE_SCN_ALIGN_2048BYTES",
	IMAGE_SCN_ALIGN_4096BYTES, "IMAGE_SCN_ALIGN_4096BYTES",
	IMAGE_SCN_ALIGN_8192BYTES, "IMAGE_SCN_ALIGN_8192BYTES",
	IMAGE_SCN_ALIGN_MASK, "IMAGE_SCN_ALIGN_MASK",
	IMAGE_SCN_LNK_NRELOC_OVFL, "IMAGE_SCN_LNK_NRELOC_OVFL",
	IMAGE_SCN_MEM_DISCARDABLE, "IMAGE_SCN_MEM_DISCARDABLE",
	IMAGE_SCN_MEM_NOT_CACHED, "IMAGE_SCN_MEM_NOT_CACHED",
	IMAGE_SCN_MEM_NOT_PAGED, "IMAGE_SCN_MEM_NOT_PAGED",
	IMAGE_SCN_MEM_SHARED, "IMAGE_SCN_MEM_SHARED",
	IMAGE_SCN_MEM_EXECUTE, "IMAGE_SCN_MEM_EXECUTE",
	IMAGE_SCN_MEM_READ, "IMAGE_SCN_MEM_READ",
	IMAGE_SCN_MEM_WRITE, "IMAGE_SCN_MEM_WRITE",
	IMAGE_SCN_SCALE_INDEX, "IMAGE_SCN_SCALE_INDEX",
};

IntStr directories[] = {
	IMAGE_DIRECTORY_ENTRY_EXPORT, "IMAGE_DIRECTORY_ENTRY_EXPORT",
    IMAGE_DIRECTORY_ENTRY_IMPORT, "IMAGE_DIRECTORY_ENTRY_IMPORT",
    IMAGE_DIRECTORY_ENTRY_RESOURCE, "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
    IMAGE_DIRECTORY_ENTRY_SECURITY, "IMAGE_DIRECTORY_ENTRY_SECURITY",
    IMAGE_DIRECTORY_ENTRY_BASERELOC, "IMAGE_DIRECTORY_ENTRY_BASERELOC",
    IMAGE_DIRECTORY_ENTRY_DEBUG, "IMAGE_DIRECTORY_ENTRY_DEBUG",
    7, "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE",
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR, "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
    IMAGE_DIRECTORY_ENTRY_TLS, "IMAGE_DIRECTORY_ENTRY_TLS",
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
    IMAGE_DIRECTORY_ENTRY_IAT, "IMAGE_DIRECTORY_ENTRY_IAT",
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
};

const char *IdToString(int id, IntStr map[]) {
	for (int i = 1; i <= map[0].id; i++)
		if (id == map[i].id) return map[i].str;
	return "Unknown";
}

#endif // _MAPS_H_