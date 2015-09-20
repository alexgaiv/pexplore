#ifndef _NTOUTPUT_H_
#define _NTOUTPUT_H_

#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include "common.h"
#include "maps.h"

using namespace std;

ostream &WriteChrs(ostream &os, DWORD chrs, int pad, IntStr map[])
{
	if (chrs == 0)
		os << "0";
	else {
		bool first = false;
		for (int i = 1; i <= map[0].id; i++) {
			if (chrs & map[i].id) {
				if (first) {
					os << left << setw(pad+3) << " |\n";
				}
				os << map[i].str;
				first = true;
			}
		}
	}
	return os;
}

ostream &operator<<(ostream &os, const IMAGE_DOS_HEADER &hdr)
{
	os << "IMAGE_DOS_HEADER {\n";
	os << "    e_magic    = " << showbase << hex << IdToString(hdr.e_magic, signature) << ",\n";
	os << "    e_cblp     = " << dec << hdr.e_cblp << ",\n";
	os << "    e_cp       = " << hdr.e_cp << ",\n";
	os << "    e_crlc     = " << hdr.e_crlc<< ",\n";
	os << "    e_cparhdr  = " << hdr.e_cparhdr << ",\n";
	os << "    e_minalloc = " << hdr.e_minalloc << ",\n";
	os << "    e_maxalloc = " << hdr.e_maxalloc << ",\n";
	os << "    e_ss       = " << hex << hdr.e_ss << ",\n";
	os << "    e_sp       = " << hdr.e_sp << ",\n";
	os << "    e_csum     = " << hdr.e_csum << ",\n";
	os << "    e_ip       = " << hdr.e_ip << ",\n";
	os << "    e_cs       = " << hdr.e_cs << ",\n";
	os << "    e_lfarlc   = " << hdr.e_lfarlc << ",\n";
	os << "    e_ovno     = " << dec << hdr.e_ovno << ",\n";
	os << "    e_res[4]   = [reserved],\n"; 
	os << "    e_oemid    = " << hex << hdr.e_oemid << ",\n";
	os << "    e_oeminfo  = " << hdr.e_oeminfo << ",\n";
	os << "    e_res2[10] = [reserved],\n"; 
	os << "    e_lfanew   = " << hdr.e_lfanew << "\n}";
	return os;
}

ostream &operator<<(ostream &os, const IMAGE_FILE_HEADER &hdr)
{
	os << "    IMAGE_FILE_HEADER {\n";
	os << "        Machine              = " << IdToString(hdr.Machine, machine) << ",\n";
	os << "        NumberOfSections     = " << dec << hdr.NumberOfSections << ",\n";
    os << "        TimeDateStamp        = " << hdr.TimeDateStamp << ",\n";
    os << "        PointerToSymbolTable = " << showbase << hex << hdr.PointerToSymbolTable << ",\n";
    os << "        NumberOfSymbols      = " << dec << hdr.NumberOfSymbols << ",\n";
    os << "        SizeOfOptionalHeader = " << hdr.SizeOfOptionalHeader << ",\n";
	os << "        Characteristics      = ";
	WriteChrs(os, hdr.Characteristics, 31, characteristics) << "\n    }\n    ";
	return os;
}

ostream &operator<<(ostream &os, const IMAGE_DATA_DIRECTORY dir[IMAGE_NUMBEROF_DIRECTORY_ENTRIES])
{
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		os << "            [" << directories[i].str << "] {\n                VirtualAddress = ";
		os << showbase << hex << dir[i].VirtualAddress << ", Size = ";
		os << dec << dir[i].Size << "\n            }";
		if (i != 15) os << ',';
		os << '\n';
	}
	return os;
}

//#define oh(members) (is64 ? ntHdrs64.OptionalHeader members : ntHdrs32.OptionalHeader members)
ostream &operator<<(ostream &os, const IMAGE_NT_HEADERS32 &hdr)
{
	const IMAGE_OPTIONAL_HEADER32 &oh = hdr.OptionalHeader;

	os << "IMAGE_NT_HEADERS {\n";
	os << "    Signature = " << IdToString(hdr.Signature, signature) << ",\n";
	os << hdr.FileHeader;
	os << "IMAGE_OPTIONAL_HEADER {\n";
	os << "        Magic                       = " << IdToString(oh.Magic, ntsignature) << ",\n";
	os << "        MajorLinkerVersion          = " << dec << (int)oh.MajorLinkerVersion << ",\n";
	os << "        MinorLinkerVersion          = " << (int)oh.MinorLinkerVersion << ",\n";
	os << "        SizeOfCode                  = " << oh.SizeOfCode << ",\n";
	os << "        SizeOfInitializedData       = " << oh.SizeOfInitializedData << ",\n";
	os << "        SizeOfUninitializedData     = " << oh.SizeOfUninitializedData << ",\n";
	os << "        AddressOfEntryPoint         = " << showbase << hex << oh.AddressOfEntryPoint << ",\n";
	os << "        BaseOfCode                  = " << hex << oh.BaseOfCode << ",\n";
	os << "        BaseOfData                  = " << oh.BaseOfData << ",\n";
	os << "        ImageBase                   = " << oh.ImageBase << ",\n";
	os << "        SectionAlignment            = " << dec << oh.SectionAlignment << ",\n";
	os << "        FileAlignment               = " << oh.FileAlignment << ",\n";
	os << "        MajorOperatingSystemVersion = " << oh.MajorOperatingSystemVersion << ",\n";
	os << "        MinorOperatingSystemVersion = " << oh.MinorOperatingSystemVersion << ",\n";
	os << "        MajorImageVersion           = " << oh.MajorImageVersion << ",\n";
	os << "        MinorImageVersion           = " << oh.MinorImageVersion << ",\n";
	os << "        MajorSubsystemVersion       = " << oh.MajorSubsystemVersion << ",\n";
	os << "        MinorSubsystemVersion       = " << oh.MinorSubsystemVersion << ",\n";
	os << "        Win32VersionValue           = " << oh.Win32VersionValue << ",\n";
	os << "        SizeOfImage                 = " << oh.SizeOfImage << ",\n";
	os << "        SizeOfHeaders               = " << oh.SizeOfHeaders << ",\n";
	os << "        CheckSum                    = " << hex << oh.CheckSum << ",\n";
	os << "        Subsystem                   = " << IdToString(oh.Subsystem, subsystem) << ",\n";
	os << "        DllCharacteristics          = ";
	WriteChrs(os, oh.DllCharacteristics, 38, dllcharacteristics) << ",\n";
	os << "        SizeOfStackReserve          = " << dec << oh.SizeOfStackReserve << ",\n";
	os << "        SizeOfStackCommit           = " << oh.SizeOfStackCommit << ",\n";
	os << "        SizeOfHeapReserve           = " << oh.SizeOfHeapReserve << ",\n";
	os << "        SizeOfHeapCommit            = " << oh.SizeOfHeapCommit << ",\n";
	os << "        LoaderFlags                 = " << hex << oh.LoaderFlags << ",\n";
	os << "        NumberOfRvaAndSizes         = " << dec << oh.NumberOfRvaAndSizes << ",\n";
	os << "        DataDirectory               = {\n";
	os << oh.DataDirectory << "        }\n    }\n}";
	return os;
}

ostream &operator<<(ostream &os, const IMAGE_NT_HEADERS64 &hdr)
{
	const IMAGE_OPTIONAL_HEADER64 &oh = hdr.OptionalHeader;

	os << "IMAGE_NT_HEADERS {\n";
	os << "    Signature = " << IdToString(hdr.Signature, signature) << ",\n";
	os << hdr.FileHeader;
	os << "IMAGE_OPTIONAL_HEADER {\n";
	os << "        Magic                       = " << IdToString(oh.Magic, ntsignature) << ",\n";
	os << "        MajorLinkerVersion          = " << dec << (int)oh.MajorLinkerVersion << ",\n";
	os << "        MinorLinkerVersion          = " << (int)oh.MinorLinkerVersion << ",\n";
	os << "        SizeOfCode                  = " << oh.SizeOfCode << ",\n";
	os << "        SizeOfInitializedData       = " << oh.SizeOfInitializedData << ",\n";
	os << "        SizeOfUninitializedData     = " << oh.SizeOfUninitializedData << ",\n";
	os << "        AddressOfEntryPoint         = " << showbase << hex << oh.AddressOfEntryPoint << ",\n";
	os << "        BaseOfCode                  = " << hex << oh.BaseOfCode << ",\n";
	os << "        ImageBase                   = " << oh.ImageBase << ",\n";
	os << "        SectionAlignment            = " << dec << oh.SectionAlignment << ",\n";
	os << "        FileAlignment               = " << oh.FileAlignment << ",\n";
	os << "        MajorOperatingSystemVersion = " << oh.MajorOperatingSystemVersion << ",\n";
	os << "        MinorOperatingSystemVersion = " << oh.MinorOperatingSystemVersion << ",\n";
	os << "        MajorImageVersion           = " << oh.MajorImageVersion << ",\n";
	os << "        MinorImageVersion           = " << oh.MinorImageVersion << ",\n";
	os << "        MajorSubsystemVersion       = " << oh.MajorSubsystemVersion << ",\n";
	os << "        MinorSubsystemVersion       = " << oh.MinorSubsystemVersion << ",\n";
	os << "        Win32VersionValue           = " << oh.Win32VersionValue << ",\n";
	os << "        SizeOfImage                 = " << oh.SizeOfImage << ",\n";
	os << "        SizeOfHeaders               = " << oh.SizeOfHeaders << ",\n";
	os << "        CheckSum                    = " << hex << oh.CheckSum << ",\n";
	os << "        Subsystem                   = " << IdToString(oh.Subsystem, subsystem) << ",\n";
	os << "        DllCharacteristics          = ";
	WriteChrs(os, oh.DllCharacteristics, 38, dllcharacteristics) << ",\n";
	os << "        SizeOfStackReserve          = " << dec << oh.SizeOfStackReserve << ",\n";
	os << "        SizeOfStackCommit           = " << oh.SizeOfStackCommit << ",\n";
	os << "        SizeOfHeapReserve           = " << oh.SizeOfHeapReserve << ",\n";
	os << "        SizeOfHeapCommit            = " << oh.SizeOfHeapCommit << ",\n";
	os << "        LoaderFlags                 = " << hex << oh.LoaderFlags << ",\n";
	os << "        NumberOfRvaAndSizes         = " << dec << oh.NumberOfRvaAndSizes << ",\n";
	os << "        DataDirectory               = {\n";
	os <<  oh.DataDirectory << "        }\n    }\n}";
	return os;
}

ostream &operator<<(ostream &os, const IMAGE_SECTION_HEADER &s)
{
	char pzname[IMAGE_SIZEOF_SHORT_NAME+1] = { };
	for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++)
		pzname[i] = s.Name[i];

	os << "IMAGE_SECTION_HEADER {\n";
	os << "    Name = " << pzname << ",\n";
	os << "    Misc = {\n";
	os << "        PhysicalAddress = " << showbase << hex << s.Misc.PhysicalAddress << ",\n";
	os << "        VirtualSize     = " << dec << s.Misc.VirtualSize << "\n    },\n";
	os << "    VirtualAddress       = " << hex << s.VirtualAddress << ",\n";
	os << "    SizeOfRawData        = " << dec << s.SizeOfRawData << ",\n";
	os << "    PointerToRawData     = " << hex << s.PointerToRawData << ",\n";
	os << "    PointerToRelocations = " << s.PointerToRelocations << ",\n";
	os << "    PointerToLinenumbers = " << s.PointerToLinenumbers << ",\n";
	os << "    NumberOfRelocations  = " << dec << s.NumberOfRelocations << ",\n";
	os << "    NumberOfLinenumbers  = " << dec << s.NumberOfLinenumbers << ",\n";
	os << "    Characteristics      = ";
	WriteChrs(os, s.Characteristics, 27, scncharacteristics) << "\n}";

	return os;
}

ostream &operator<<(ostream &os, const IMAGE_EXPORT_DIRECTORY &e)
{
	char *name = 0;
	int diff = GetRvaDelta(e.Name);
	ReadZString(hFile, e.Name - diff, name);

	os << "IMAGE_EXPORT_DIRECTORY {\n";
	os << "    Characteristics       = " << showbase << hex << e.Characteristics << ",\n";
	os << "    TimeDateStamp         = " << dec << e.TimeDateStamp << ",\n";
	os << "    MajorVersion          = " << e.MajorVersion << ",\n";
	os << "    MinorVersion          = " << e.MinorVersion << ",\n";
	os << "    Name                  = " << hex << e.Name << " -> " << name << ",\n";
	os << "    Base                  = " << dec << e.Base << ",\n";
	os << "    NumberOfFunctions     = " << e.NumberOfFunctions << ",\n";
	os << "    NumberOfNames         = " << e.NumberOfNames << ",\n";
	os << "    AddressOfFunctions    = " << hex << e.AddressOfFunctions << ",\n";
	os << "    AddressOfNames        = " << e.AddressOfNames << ",\n";
	os << "    AddressOfNameOrdinals = " << e.AddressOfNameOrdinals << "\n}";
	delete[] name;
	return os;
}

ostream &operator<<(ostream &os, const IMAGE_IMPORT_DESCRIPTOR &im)
{
	char *name = 0;
	int diff = GetRvaDelta(im.Name);
	ReadZString(hFile, im.Name - diff, name);

	os << "IMAGE_IMPORT_DESCRIPTOR {\n";
	os << "    OriginalFirstThunk = " << showbase << hex << im.OriginalFirstThunk << ",\n";
    os << "    TimeDateStamp      = " << dec << im.TimeDateStamp << ",\n";
    os << "    ForwarderChain     = " << hex << im.ForwarderChain << ",\n";
    os << "    Name               = " << im.Name << " -> " << name << ",\n";
    os << "    FirstThunk         = " << im.FirstThunk << "\n}";
	delete[] name;
	return os;
}

ostream &operator<<(ostream &os, const IMAGE_THUNK_DATA &t)
{
	cout << "IMAGE_THUNK_DATA {\n";
	if (IMAGE_SNAP_BY_ORDINAL(t.u1.Ordinal)) {
		cout << "    Ordinal = " << t.u1.Ordinal << "\n}";
	} else {
		int diff = GetRvaDelta(t.u1.AddressOfData);
		DWORD impByNamePtr = t.u1.AddressOfData - diff;

		WORD hint = 0;
		char *name = 0;
		ReadFileAt(hFile, &hint, sizeof(WORD), impByNamePtr);
		ReadZString(hFile, impByNamePtr + sizeof(WORD), name);

		cout << "    AddressOfData = " << showbase << hex << t.u1.AddressOfData << " ->\n";
		cout << "        IMPORT_BY_NAME {\n";
		cout << "            Hint = " << hint << ",\n";
		cout << "            Name = " << name << "\n        }\n}";
		delete[] name;
	}
	return os;
}

#endif // _NTOUTPUT_H_