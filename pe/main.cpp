#include <Windows.h>
#include <winnt.h>
#include <delayimp.h>
#include <iostream>
#include <iomanip>
#include "common.h"
#include "ntoutput.h"

using namespace std;

const char *commandNames[6] = { "/ALL", "/HEADERS", "/SECTIONS", "/EXPORTS", "/IMPORTS", "/DELAYLOAD" };

bool is64 = false;
HANDLE hFile = INVALID_HANDLE_VALUE;
IMAGE_DOS_HEADER dosHdr = { };
IMAGE_NT_HEADERS32 ntHdrs32 = { };
IMAGE_NT_HEADERS64 ntHdrs64 = { };
IMAGE_SECTION_HEADER *sections = NULL;
int numSections = 0;

void SetupPE(const char *filename)
{
	hFile = CreateFileA(filename, GENERIC_READ,
		FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (FAILED(hFile)) throw "cannot open file";

	ReadFileAt(hFile, &dosHdr, sizeof(dosHdr));
	if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
		throw "DOS header test failed";

	WORD magic = 0;
	ReadFileAt(hFile, &magic, sizeof(magic), dosHdr.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	is64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

	if (is64)
		ReadFileAt(hFile, &ntHdrs64, sizeof(ntHdrs64), dosHdr.e_lfanew);
	else ReadFileAt(hFile, &ntHdrs32, sizeof(ntHdrs32), dosHdr.e_lfanew);

	if (NTHDRS(.Signature) != IMAGE_NT_SIGNATURE)
		throw "NT header test failed";

	numSections = NTHDRS(.FileHeader.NumberOfSections);
	sections = new IMAGE_SECTION_HEADER[numSections];

	DWORD bytesRead = 0;
	for (int i = 0; i < numSections; i++) {
		ReadFileAt(hFile, &sections[i], sizeof(IMAGE_SECTION_HEADER));
	}
}

void PrintExports()
{
	IMAGE_DATA_DIRECTORY dir = NTHDRS(.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (dir.VirtualAddress == 0 || dir.Size == 0) {
		cout << "\n[file does not export any functions]\n";
		return;
	}

	IMAGE_EXPORT_DIRECTORY exportsDir = { };
	int exportsDiff = GetRvaDelta(dir.VirtualAddress);
	ReadFileAt(hFile, &exportsDir, sizeof(exportsDir), dir.VirtualAddress - exportsDiff);

	cout << "\n[export information]\n" << exportsDir << endl;

	int numFunctions = exportsDir.NumberOfFunctions;
	int numNames = exportsDir.NumberOfNames;
	DWORD *functions = new DWORD[numFunctions];
	DWORD *names = new DWORD[numNames];
	WORD *ordinals = new WORD[numNames];
	DWORD funcRawPtr = exportsDir.AddressOfFunctions - exportsDiff;
	DWORD nameRawPtr = exportsDir.AddressOfNames - exportsDiff;
	DWORD ordRawPtr = exportsDir.AddressOfNameOrdinals - exportsDiff;

	ReadFileAt(hFile, functions, numFunctions*4, funcRawPtr);
	ReadFileAt(hFile, names, numNames*4, nameRawPtr);
	ReadFileAt(hFile, ordinals, numNames*2, ordRawPtr);

	cout.fill('\xc4');
	cout << right << "\xda" << setw(8) << "\xc2" << setw(13) << "\xc2" << setw(58) << "\xbf\n";
	cout << "\xb3  Ord  \xb3    RVA     \xb3                          Name                          \xb3\n";
	cout << right << "\xc3" << setw(8) << "\xc5" << setw(13) << "\xc5" << setw(58) << "\xb4\n";
	cout.fill(' ');

	for (int i = 0; i < numNames; i++)
	{
		char *buf = 0;
		ReadZString(hFile, names[i] - exportsDiff, buf);

		DWORD entryPoint = functions[ordinals[i]];
		cout << "\xb3 ";
		cout << left << dec << setw(5) << ordinals[i] << " \xb3 ";
		cout << hex << setw(10) << entryPoint << " \xb3 ";
		cout << setw(55) << buf << "\xb3\n";
		delete[] buf;

		if (entryPoint >= dir.VirtualAddress && entryPoint <= dir.VirtualAddress + dir.Size) {
			int addr = entryPoint - GetRvaDelta(entryPoint);
			ReadZString(hFile, addr, buf);
			cout << "\xb3" << right << setw(8) << "\xb3" << setw(13) << "\xb3";
			cout << "     forwarded to " << left << setw(38) << buf << "\xb3\n";
			delete[] buf;
		}
		
	}
	cout.fill('\xc4');
	cout << right << "\xc0" << setw(8) << "\xc1" << setw(13) << "\xc1" << setw(58) << "\xd9\n";
	cout.fill(' ');

	delete[] functions;
	delete[] names;
	delete[] ordinals;
}

void PrintImports()
{
	IMAGE_DATA_DIRECTORY dir = NTHDRS(.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	if (dir.VirtualAddress == 0 || dir.Size == 0) {
		cout << "\n[file does not import any functions]\n";
		return;
	}

	IMAGE_IMPORT_DESCRIPTOR importDesc = { };
	IMAGE_THUNK_DATA thunk = { };
	
	cout << "\n[import information]\n";
	int importsDiff = GetRvaDelta(dir.VirtualAddress);
	DWORD importsPtr = dir.VirtualAddress - importsDiff;

	cout.fill('\xc4');
	cout << right << "\xda" << setw(35) << "\xc2" << setw(8) << "\xc2" << setw(36) << "\xbf\n";
	cout << "\xb3             Library              \xb3 Hint  \xb3             Functions            \xb3\n";
	cout << right << "\xc3" << setw(35) << "\xc5" << setw(8) << "\xc5" << setw(36) << "\xb4\n";
	cout.fill(' ');

	ReadFileAt(hFile, &importDesc, sizeof(importDesc), importsPtr);
	do {
		if (importDesc.Characteristics == 0) break;
		int thunkDiff = GetRvaDelta(importDesc.OriginalFirstThunk);

		char *lib_name = 0;
		ReadZString(hFile, importDesc.Name - thunkDiff, lib_name);
		cout << "\xb3";
		cout << left << setw(33) << lib_name;
		delete[] lib_name;

		for(int i = 0, f = 1; ;i++) {
			if (f) ReadFileAt(hFile, &thunk, sizeof(thunk), importDesc.OriginalFirstThunk - thunkDiff + i*sizeof(thunk));
			
			bool func_ended = !f || thunk.u1.Function == 0;
			if (func_ended && i > 5) break;

			if (i != 0) cout << "\xb3 ";
			cout.setf(ios::left, ios::adjustfield);
			switch (i)
			{
			case 0: break;
			case 1: cout << " OriginalFirstThunk = " << showbase << hex << left << setw(10) << importDesc.OriginalFirstThunk;
				break;
			case 2: cout << " TimeDateStamp      = " << dec << setw(10) << importDesc.TimeDateStamp;
				break;
			case 3: cout << " ForwarderChain     = " << hex << setw(10) << importDesc.ForwarderChain;
				break;
			case 4: cout << " Name               = " << hex << setw(10) << importDesc.Name;
				break;
			case 5: cout << " FirstThunk         = " << hex << setw(10) << importDesc.FirstThunk;
				break;
			default:
				cout.width(35);
			}

			if (func_ended) {
				f = 0;
				if (i <= 5) {
					cout << " \xb3" << right << setw(8) << "\xb3" << right << setw(36) << "\xb3\n";
					continue;
				}
				break;
			}

			int diff = GetRvaDelta(thunk.u1.AddressOfData);
			DWORD impByNamePtr = thunk.u1.AddressOfData - diff;

			WORD hint = 0;
			char *func_name = 0;
			ReadFileAt(hFile, &hint, sizeof(WORD), impByNamePtr);
			ReadZString(hFile, impByNamePtr + sizeof(WORD), func_name);

			cout << right << " \xb3 " << left << setw(6) << dec << hint << "\xb3 " << setw(33) << func_name << "\xb3\n";

			delete[] func_name;
		}

		importsPtr += sizeof(importDesc);
		ReadFileAt(hFile, &importDesc, sizeof(importDesc), importsPtr);

		cout.fill('\xc4');
		if (importDesc.Characteristics != 0)
			cout << right << "\xc3" << setw(35) << "\xc5" << setw(8) << "\xc5" << setw(36) << "\xb4\n";
		cout.fill(' ');

	} while (true);

	cout.fill('\xc4');
	cout << right << "\xc0" << setw(35) << "\xc1" << setw(8) << "\xc1" << setw(36) << "\xd9\n";
	cout.fill(' ');
}

void PrintDelayLoad()
{
	IMAGE_DATA_DIRECTORY dir = NTHDRS(.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
	if (dir.VirtualAddress == 0 || dir.Size == 0) {
		return;
	}
	
	cout << "\n[delay loaded DLLs]\n";
	ImgDelayDescr delayDesc = { };
	int delayDiff = GetRvaDelta(dir.VirtualAddress);
	DWORD delayPtr = dir.VirtualAddress - delayDiff;

	char *buf = 0;
	
	while (true) {
		ReadFileAt(hFile, &delayDesc, sizeof(delayDesc), delayPtr);
		if (!delayDesc.rvaDLLName) break;

		int diff = GetRvaDelta(delayDesc.rvaDLLName);
		ReadZString(hFile, delayDesc.rvaDLLName - diff, buf);
		cout << buf << endl;
		delete[] buf;
		delayPtr += sizeof(ImgDelayDescr);
	}
}

void ShowHelp()
{
	cout << "usage: PE [options] [file]\n\n";
	cout << "   options:\n";
	for (int i = 0; i < 5; i++) {
		cout << "      " << commandNames[i] << endl;
	}
}

void ParseCommandLine(int argc, char *argv[])
{
	bool fCommand = false;
	bool commands[6] = { };
	bool *otherParams = new bool[argc];
	memset(otherParams, 0, argc*sizeof(bool));

	for (int i = 1; i < argc; i++)
	{
		bool fOther = true;
		for (int k = 0; k < 6; k++) {
			if (mystrcmp(argv[i], commandNames[k])) {
				commands[k] = true;
				fCommand = true;
				fOther = false;
				break;
			}
		}
		if (fOther) otherParams[i] = true;
	}

	if (!fCommand || commands[0])
		memset(commands, 1, 6*sizeof(bool));

	char *filename = NULL;
	for (int i = argc - 1; i >= 0; i--) {
		if (otherParams[i]) {
			if (!filename && argv[i][0] != '/') filename = argv[i];
			else {
				cout << "Warning: unknown command " << argv[i] << "; ignored\n";
			}
		}
	}
	delete[] otherParams;

	if (!filename) {
		if (IsDebuggerPresent()) {
			filename = "C:/Windows/System32/user32.dll";
		}
		else {
			ShowHelp();
			return;
		}
		
	}

	cout << "dump of file: " << filename << endl;

	SetupPE(filename);
	cout << "file is a valid PE\n\n";

	if (commands[1]) {
		cout << dosHdr << endl;
		if (is64) cout << ntHdrs64;
		else cout << ntHdrs32;
		cout << endl;
	}
	if (commands[2]) {
		for (int i = 0; i < numSections; i++)
			cout << sections[i] << endl;
	}
	if (commands[3]) PrintExports();
	if (commands[4]) PrintImports();
	if (commands[5]) PrintDelayLoad();
}

int main(int argc, char *argv[])
{	
	try {
		ParseCommandLine(argc, argv);
	}
	catch(const char *errMsg) {
		cout << "Error: " << errMsg << endl;
	}

	if (SUCCEEDED(hFile)) CloseHandle(hFile);
	if (sections) delete[] sections;

	system("pause");
	return 0;
}