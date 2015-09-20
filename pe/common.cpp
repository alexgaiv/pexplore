#include "common.h"

void ReadFileAt(HANDLE file, LPVOID buffer, DWORD bytesToRead, DWORD filePointer)
{
	DWORD bytesRead = 0;
	if (filePointer) SetFilePointer(file, filePointer, NULL, FILE_BEGIN);
	ReadFile(file, buffer, bytesToRead, &bytesRead, NULL);
	if (bytesRead != bytesToRead)
		throw "Unexpected end of file";
}

void ReadZString(HANDLE file, DWORD pointer, char *&outputBuffer)
{
	const int alloc = 40;
	int size = alloc;
	outputBuffer = new char[size];
	bool z = false;
	while (!z) {
		int d = size - alloc;
		ReadFileAt(file, outputBuffer + d, alloc, pointer + d);
		for (int i = d; i < size && !z; i++) {
			if (!outputBuffer[i]) z = true;
		}
		if (!z) {
			char *tmp = new char[size + alloc];
			memcpy(tmp, outputBuffer, size);
			delete[] outputBuffer;
			outputBuffer = tmp;
			size += alloc;
		}
	}
}

int GetRvaSection(DWORD rva)
{
	if (rva >= sections[numSections - 1].VirtualAddress)
		return numSections - 1;
	int i = 0;
	for (; i < numSections - 1; i++) {
		if (rva < sections[i + 1].VirtualAddress) break;
	}
	return i;
}

int GetRvaDelta(DWORD rva)
{
	IMAGE_SECTION_HEADER &dirSection = sections[GetRvaSection(rva)];
	return (signed)dirSection.VirtualAddress - (signed)dirSection.PointerToRawData;
}