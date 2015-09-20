#ifndef _COMMON_H_
#define _COMMON_H_

#include <Windows.h>

extern bool is64;
extern HANDLE hFile;
extern IMAGE_DOS_HEADER dosHdr;
extern IMAGE_NT_HEADERS32 ntHdrs32;
extern IMAGE_NT_HEADERS64 ntHdrs64;
extern IMAGE_SECTION_HEADER *sections;
extern int numSections;

#define NTHDRS(members) (is64 ? (ntHdrs64 members) : (ntHdrs32 members))

void ReadFileAt(HANDLE file, LPVOID buffer, DWORD bytesToRead, DWORD filePointer = 0);
void ReadZString(HANDLE file, DWORD pointer, char *&outputBuffer);
int GetRvaSection(DWORD rva);
int GetRvaDelta(DWORD rva);

inline bool mystrcmp(const char *s1, const char *s2)
{
	while (*s1 || *s2) {
		if (tolower(*s1) != tolower(*s2)) return false;
		s1++; s2++;
	}
	return true;
}

#endif // _COMMON_H_