//Author: Jeremy


#include "stdafx.h"
#include "PeLoader.h"
#include "Exception.h"

#include <memory>
#include <TlHelp32.h>
#include <sstream>
#include <iostream>

using namespace PeLoaderLib;

PeLoader::PeLoader(const std::string& sLibraryName)
{
	char sLibraryPath[MAX_PATH];

	m_sLibraryName = sLibraryName;

	//Search directorys other than the working directory (i.e, system32); otherwise attempts to load librarys such as user32.dll will fail.
	if(!SearchPathA(0, sLibraryName.c_str(), 0, MAX_PATH, sLibraryPath, 0))
		throw Exception("Unable to locate library.");

	//Map the file in to memory for quick IO and easy read access.
	HANDLE hFile = CreateFileA(sLibraryPath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if(hFile == INVALID_HANDLE_VALUE)
		throw Exception("Unable to open file.");

	//Attempt to create file mapping object.
	HANDLE hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);

	if(!hFileMap)
		throw Exception("Error create file mapping.");

	//Attempt to map file in to local address space.
	void* pFileView = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	
	if(!pFileView)
		throw Exception("Error mapping view of file in to local address space.");

	init(pFileView, hFile, hFileMap);
}


PeLoader::PeLoader(const void* pSourceImage)
{
	init(pSourceImage);
}

PeLoader::~PeLoader()
{
	//Unmap file view
	if(m_hFileMap)
	{
		UnmapViewOfFile(m_pFileView);
		CloseHandle(m_hFileMap);
		CloseHandle(m_hFile);
	}
}

void PeLoader::init(const void* pView, const HANDLE hFile, const HANDLE hFileMap)
{
	m_pFileView = const_cast<void*>(pView);
	m_hFile = hFile;
	m_hFileMap = hFileMap;

	//Initilize file DOS and NT headers.
	m_pFileDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(m_pFileView);

	//Validate DOS headers
	if(!isValidDosHeader(m_pFileDosHeader))
		throw Exception("Invalid DOS header.");

	m_pFileNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(m_pFileDosHeader->e_lfanew + reinterpret_cast<LONG>(m_pFileView));

	//Validate NT Headers
	if(!isValidNtHeaders(m_pFileNtHeaders))
		throw Exception("Invalid NT Headers.");
}

bool PeLoader::isValidNtHeaders(const IMAGE_NT_HEADERS* pNtHeaders)
{
	return (pNtHeaders->Signature == 'EP');
}

bool PeLoader::isValidDosHeader(const IMAGE_DOS_HEADER* pDosHeader)
{
	return (pDosHeader->e_magic == 'ZM');
}

void PeLoader::calculateRelocation(const HANDLE hProc, const long difference, const unsigned long ulBase, const WORD wOffset)
{
	const unsigned long relocationType = wOffset>>12;
	const unsigned long ulDest = (wOffset & (0xFFF));

	switch(relocationType)
	{
	//Only required relocations on an x86 system.
	case IMAGE_REL_BASED_HIGHLOW:
		{
			DWORD buffer = 0;

			if(!ReadProcessMemory(hProc, reinterpret_cast<unsigned long*>(ulDest + ulBase), &buffer, sizeof(buffer), 0))
				throw Exception("Error reading relocation data.");

			buffer += difference;
		
			if(!WriteProcessMemory(hProc, reinterpret_cast<unsigned long*>(ulDest + ulBase), &buffer, sizeof(buffer),0))
				throw Exception("Error applying relocations data.");
		}
		break;
	case IMAGE_REL_BASED_ABSOLUTE:
	default:
		break;
	};
}

void PeLoader::setSectionPermissions(const HANDLE hProc, const void* pAddress, const unsigned long ulSize, const unsigned long ulCharacteristics)
{
	//Correct section permissions.
	unsigned long ulPermissions = 0;

	if(ulCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		ulPermissions = PAGE_EXECUTE;
			
	if(ulCharacteristics & IMAGE_SCN_MEM_READ)
		ulPermissions = PAGE_READONLY;
			
	if(ulCharacteristics & IMAGE_SCN_MEM_WRITE)
		ulPermissions = PAGE_READWRITE;
		
	if((ulCharacteristics & IMAGE_SCN_MEM_EXECUTE) && ulPermissions == PAGE_READWRITE)
		ulPermissions = PAGE_EXECUTE_READWRITE;

	if((ulCharacteristics & IMAGE_SCN_MEM_EXECUTE) && ulPermissions == PAGE_READONLY)
		ulPermissions = PAGE_EXECUTE_READ;

	if(!VirtualProtectEx(hProc, const_cast<void*>(pAddress), ulSize, ulPermissions, &ulPermissions))
		throw Exception("Error applying page protection.");
}

HMODULE PeLoader::getLibrary(const HANDLE hProc, const std::string& sLibraryName)
{
	//convert multibyte string to wchar string; required because module names granted via snapshot are wide-character.
	std::wstring swName(sLibraryName.begin(), sLibraryName.end());

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProc));
	
	if(hSnapshot == INVALID_HANDLE_VALUE)
		throw Exception("Error creating snapshot of remote process.");

	MODULEENTRY32 moduleInfo;
	ZeroMemory(&moduleInfo, sizeof(moduleInfo));
	moduleInfo.dwSize = sizeof(moduleInfo);

	if(!Module32First(hSnapshot, &moduleInfo))
		throw Exception("Error getting first module in remote process.");

	do
	{
		if(!_wcsicmp(moduleInfo.szModule, swName.c_str()))
			return reinterpret_cast<HMODULE>(moduleInfo.modBaseAddr);

	}while(Module32Next(hSnapshot, &moduleInfo));

	CloseHandle(hSnapshot);

	return 0;
}

//Works exactly like GetProcAddressA, only it takes a HANDLE, thus it can be used to get a procedure address from a remote process.
void* PeLoader::getRemoteProcAddress(const HANDLE hProc, const HMODULE hModule, const char* sProcName)
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeaders;

	if(!ReadProcessMemory(hProc, hModule, &dosHeader, sizeof(IMAGE_DOS_HEADER), 0))
		throw Exception("Error reading dos header from remote process.");
	
	if(!isValidDosHeader(&dosHeader))
		throw Exception("Invalid DOS Header.");

	if(!ReadProcessMemory(hProc, reinterpret_cast<void*>(dosHeader.e_lfanew + reinterpret_cast<unsigned long>(hModule)), &ntHeaders, sizeof(ntHeaders), 0))
		throw Exception("Error reading image nt headers from remote process.");
	
	if(!isValidNtHeaders(&ntHeaders))
		throw Exception("Invalid PE Headers.");

	IMAGE_EXPORT_DIRECTORY exportDirectory;

	if(!ReadProcessMemory(hProc, 
		reinterpret_cast<void*>(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + reinterpret_cast<unsigned long>(hModule)), 
		&exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), 0))
		throw Exception("Error reading export directory from remote process.");
	
	std::auto_ptr<DWORD> functionRvas(new DWORD[exportDirectory.NumberOfFunctions]);
	
	if(!ReadProcessMemory(hProc, reinterpret_cast<void*>(exportDirectory.AddressOfFunctions + reinterpret_cast<unsigned long>(hModule)), functionRvas.get(), sizeof(DWORD) * exportDirectory.NumberOfFunctions, 0))
		throw Exception("Error reading export names table.");

	//Buffer used to store RVA of function, when (if) it is found.
	unsigned long ulRvaBuffer = 0;
	
	//This is how MSDN defines the nature of GetProcAddress, so we will create getRemoteProcAddress in the same way. If the HIWORD is set, then sProcName is treated as a name, otherwise as an ordinal.
	if(HIWORD(sProcName))
	{
		std::auto_ptr<DWORD> nameRvas(new DWORD[exportDirectory.NumberOfNames]);
		std::auto_ptr<WORD>  nameOrdinalRvas(new WORD[exportDirectory.NumberOfNames]);

		//Search for api via name
		if(!ReadProcessMemory(hProc, reinterpret_cast<void*>(exportDirectory.AddressOfNames + reinterpret_cast<unsigned long>(hModule)), nameRvas.get(), sizeof(DWORD) * exportDirectory.NumberOfNames, 0))
			throw Exception("Error reading export names table.");

		//Search for api via name
		if(!ReadProcessMemory(hProc, reinterpret_cast<void*>(exportDirectory.AddressOfNameOrdinals + reinterpret_cast<unsigned long>(hModule)), nameOrdinalRvas.get(), sizeof(WORD) * exportDirectory.NumberOfNames, 0))
			throw Exception("Error reading export ordinal table.");
		
		std::auto_ptr<char> sNameBuffer(new char[strlen(sProcName) + 1]);
		for(unsigned int i = 0; i < exportDirectory.NumberOfNames; i++)
		{
			if(!ReadProcessMemory(hProc, reinterpret_cast<void*>(nameRvas.get()[i] + reinterpret_cast<unsigned long>(hModule)), sNameBuffer.get(), strlen(sProcName) + 1, 0))
				throw Exception("Error reading import name.");

			if(!strcmp(sNameBuffer.get(), sProcName))
				ulRvaBuffer = functionRvas.get()[nameOrdinalRvas.get()[i]];
		}
	}else
	{
		ulRvaBuffer = functionRvas.get()[reinterpret_cast<DWORD>(sProcName)];
	}

	//Check to assure RVA was found, otherwise return 0 (error)
	if(!ulRvaBuffer)
		return 0;

	//Check if it import is forwarded...
	if(ulRvaBuffer >= ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
		ulRvaBuffer < ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
	{
		char sForwardBuffer[100];

		if(!ReadProcessMemory(hProc, reinterpret_cast<void*>(ulRvaBuffer + reinterpret_cast<unsigned long>(hModule)), sForwardBuffer, sizeof(sForwardBuffer), 0))
			throw Exception("Error gathering information about forwarded symbol.");

		std::stringstream ss(sForwardBuffer);
		std::string sLibraryName;
		std::string sApiName;

		if(!std::getline(ss, sLibraryName, '.'))
			throw Exception("Error parsing export forwarding.");
					
		sLibraryName += ".dll";
		ss>>sApiName;

		HMODULE hMod = getLibrary(hProc, sLibraryName);

		if(!hMod)
			throw Exception("Error finding forwarded export; unable to find library forwarded to.");

		void* pAddress = getRemoteProcAddress(hProc, hMod, sApiName.c_str());
				
		if(!pAddress)
			throw Exception("Error finding forward API.");

		return pAddress;
	}
	else
	{
		return reinterpret_cast<void*>(ulRvaBuffer + reinterpret_cast<unsigned long>(hModule));
	}

	return 0;
}

//Locates which section corresponds to an rva.
const IMAGE_SECTION_HEADER* PeLoader::getRvaSection(const unsigned long ulRva, const IMAGE_NT_HEADERS* pNtHeaders)
{
	IMAGE_SECTION_HEADER* pSections = IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS*>(pNtHeaders));

	for(unsigned int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if(ulRva >= pSections[i].VirtualAddress &&
			ulRva < pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize)
			return &pSections[i];
	}
	
	throw Exception("Unable to resolve RVA to its parent section.");
}

//Translates an RVA to a file offset.
long PeLoader::rvaToFileOffset(const unsigned long ulRva, const IMAGE_NT_HEADERS* pNtHeaders)
{
	const IMAGE_SECTION_HEADER* pSection = getRvaSection(ulRva, pNtHeaders);

	//Calculate differene in base of section data and base of section when mounted in to memory.
	long lDelta = pSection->PointerToRawData - pSection->VirtualAddress;

	return ulRva + lDelta;
}

//Works the same as LoadLibraryA, only takes a HANDLE to which process the library is to be loaded in to.
//This invokes LoadLibraryA in the remote process and returns its base address.
HMODULE PeLoader::remoteLoadLibrary(const HANDLE hProc, const char* sLibraryName)
{
	void* pMemory = const_cast<char*>(sLibraryName);
	if(HIWORD(sLibraryName))
	{
		pMemory = VirtualAllocEx(hProc, 0, strlen(sLibraryName), MEM_COMMIT, PAGE_READWRITE);
	
		if(!pMemory)
			throw Exception("Error injecting library, unable to allocate memory for library name.");

		if(!WriteProcessMemory(hProc, pMemory, sLibraryName, strlen(sLibraryName) + 1, 0))
			throw Exception("Error injecting library, unable to access memory allocated for library name.");
	}

	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")), pMemory, 0, 0);
	
	if(!hThread)
		throw Exception("Error creating remote thread at origin of LoadLibraryA");

	//Wait for thread to terminate
	if(WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
		throw Exception("Error occured while waiting for thread; remote LoadLibraryA invocation");

	HMODULE hMod = 0;

	//Get thread's exit code (eax), which is HMODULE of the loaded library.
	if(!GetExitCodeThread(hThread, reinterpret_cast<DWORD*>(&hMod)))
		throw Exception("Error getting return code of remote thread.");

	CloseHandle(hThread);

	return hMod;
}

HMODULE PeLoader::mapLibrary(const HANDLE hProcess)
{
	void* pLibraryBase = VirtualAllocEx(hProcess, reinterpret_cast<void*>(m_pFileNtHeaders->OptionalHeader.ImageBase), m_pFileNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);

	unsigned long ul = GetLastError();

	if(!pLibraryBase)
	{
		//try loading at another address...
		pLibraryBase = VirtualAllocEx(hProcess, 0, m_pFileNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);

		if(!pLibraryBase)	
			throw Exception("Error allocating enough memory for library in process.");
	}

	IMAGE_SECTION_HEADER* pSectionHeaders = IMAGE_FIRST_SECTION(m_pFileNtHeaders);
	
	//Commit memory for PE Headers.
	if(!VirtualAllocEx(hProcess, 
		pLibraryBase, m_pFileDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + m_pFileNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), 
		MEM_COMMIT, PAGE_READWRITE))
		throw Exception("Error committing memory for DOS header.");

	//Copy the PE headers in to memory, as to allow lookup of library exports.
	if(!WriteProcessMemory(hProcess, pLibraryBase, m_pFileDosHeader, sizeof(IMAGE_DOS_HEADER), 0))
		throw Exception("Error copying dos header in to remote process.");

	if(!WriteProcessMemory(hProcess, reinterpret_cast<void*>(reinterpret_cast<unsigned long>(pLibraryBase) + m_pFileDosHeader->e_lfanew), m_pFileNtHeaders, sizeof(IMAGE_NT_HEADERS), 0))
		throw Exception("Error copying NT headers in to remote process.");

	if(!WriteProcessMemory(hProcess, 
		reinterpret_cast<void*>(reinterpret_cast<unsigned long>(pLibraryBase) + m_pFileDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)), 
		pSectionHeaders, m_pFileNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), 0))
		throw Exception("Error copying section headers in to remote process.");


	for(unsigned int i = 0; i < m_pFileNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if(pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			continue;

		void* pFileSectionAddress = reinterpret_cast<void*>(pSectionHeaders[i].PointerToRawData + reinterpret_cast<unsigned long>(m_pFileView));
		void* pMemorySectionAddress = reinterpret_cast<void*>(pSectionHeaders[i].VirtualAddress + reinterpret_cast<unsigned long>(pLibraryBase));

		unsigned long ulSectionSize = pSectionHeaders[i].SizeOfRawData;

		//Commit the memory we previously reserved for this section.
		if(VirtualAllocEx(hProcess, pMemorySectionAddress, pSectionHeaders[i].Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE) != pMemorySectionAddress)
			throw Exception("Error commiting memory for section.");

		if(ulSectionSize > 0)
		{
			if(!WriteProcessMemory(hProcess, pMemorySectionAddress, pFileSectionAddress, ulSectionSize, 0))
				throw Exception("Error copying section to remote process.");
		}
	}
	
	//Resolve image imports and setup the IAT, if there are any.
	if(m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		IMAGE_IMPORT_DESCRIPTOR* pImportDescriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(rvaToFileOffset(m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, m_pFileNtHeaders) + reinterpret_cast<unsigned long>(m_pFileView));
		for(unsigned int i = 0; pImportDescriptors[i].FirstThunk; i++)
		{
			IMAGE_THUNK_DATA* pInts = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<unsigned long>(m_pFileView) + rvaToFileOffset(pImportDescriptors[i].OriginalFirstThunk, m_pFileNtHeaders));
			IMAGE_THUNK_DATA* pIat = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<unsigned long>(pLibraryBase) + pImportDescriptors[i].FirstThunk);

			HMODULE hImportLib = remoteLoadLibrary(hProcess, reinterpret_cast<char*>(m_pFileView) + rvaToFileOffset(pImportDescriptors[i].Name, m_pFileNtHeaders));

			for(unsigned int x = 0; pInts[x].u1.Function != 0; x++)
			{
				unsigned long ulImportNameOrdinal = 0;

				if(pInts[x].u1.Function & (1>>31))
				{
					//if MSB is set, it is an ordinal.
					ulImportNameOrdinal = pInts[x].u1.Function & ~(1>>31);
				}else
				{
					IMAGE_IMPORT_BY_NAME* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<unsigned long>(m_pFileView) + rvaToFileOffset(pInts[x].u1.Function, m_pFileNtHeaders));
					ulImportNameOrdinal = reinterpret_cast<unsigned long>(pImport->Name);
				}

				void* pProcAddress = getRemoteProcAddress(hProcess, hImportLib, reinterpret_cast<const char*>(ulImportNameOrdinal));

				if(!pProcAddress)
					throw Exception("Error finding import.");

				if(!WriteProcessMemory(hProcess, &pIat[x], &pProcAddress, sizeof(void*), 0))
					throw Exception("Error writing to remote IAT.");
			}
		}
	}

	
	//Do relocations described in the Relocations data directory if required.
	if(reinterpret_cast<unsigned long>(pLibraryBase) != m_pFileNtHeaders->OptionalHeader.ImageBase && m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	{
		IMAGE_BASE_RELOCATION* pBaseRelocations = reinterpret_cast<IMAGE_BASE_RELOCATION*>(rvaToFileOffset(m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, m_pFileNtHeaders) + reinterpret_cast<unsigned long>(m_pFileView));
		for(IMAGE_BASE_RELOCATION* pCurrentRelocation = pBaseRelocations; 
			reinterpret_cast<unsigned long>(pCurrentRelocation) - reinterpret_cast<unsigned long>(pBaseRelocations) < m_pFileNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
			pCurrentRelocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<unsigned long>(pCurrentRelocation) + pCurrentRelocation->SizeOfBlock))
		{
			long difference = reinterpret_cast<unsigned long>(pLibraryBase) - m_pFileNtHeaders->OptionalHeader.ImageBase;
			unsigned long ulBase = reinterpret_cast<unsigned long>(pLibraryBase) + pCurrentRelocation->VirtualAddress;
		
			WORD* pRelocationOffsets = reinterpret_cast<WORD*>(reinterpret_cast<unsigned long>(pCurrentRelocation) + sizeof(IMAGE_BASE_RELOCATION));

			for(unsigned int i = 0; i < pCurrentRelocation->SizeOfBlock / sizeof(WORD); i++)
				calculateRelocation(hProcess, difference, ulBase, pRelocationOffsets[i]);
		}
	}
	//After code relocations, we can apply the proper page permissions.
	for(unsigned int i = 0; i < m_pFileNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if(pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			continue;

		void* pMemorySectionAddress = reinterpret_cast<void*>(pSectionHeaders[i].VirtualAddress + reinterpret_cast<unsigned long>(pLibraryBase));
		setSectionPermissions(hProcess, pMemorySectionAddress, pSectionHeaders[i].Misc.VirtualSize, pSectionHeaders[i].Characteristics);
	}

	//----------
	//Call dllmain, sort of a tricky task...

	//Data generated at run-time regarding stub.
	void* pInvocationStubBase = 0;
	unsigned long ulInvocationStubSize;

	//Small asm stub to call DllMain (It would probably be a lot easier to place this in a structure local to this function.)
	__asm
	{
		jmp lblDllMainInvocationStub_End;
lblDllMainInvocationStub_Base:
		push ebp;
		mov ebp, esp;			//Will trigger warnings, ignore them. This is not to be executed locally (well, it can be, but the context will be safe.)
		mov eax, [ebp + 0x8];

		push ecx; //reserver ecx
		
		push 0; //hinstance = 0
		push DLL_PROCESS_ATTACH; //Reason
		push eax;

		mov ecx, dword ptr[eax + 0x3C];
		add ecx, eax;
		add ecx, 40; //ECX now points to the ep of the module
		add eax, dword ptr[ecx] //Load eax with entry address

		call eax; //Call entry point

		pop ecx; //Restore ecx
		pop ebp; //restore ebp
		ret      //return to caller

lblDllMainInvocationStub_End:
		push eax;
		mov eax, lblDllMainInvocationStub_Base;
		mov pInvocationStubBase, eax;

		mov eax, lblDllMainInvocationStub_End;
		sub eax, lblDllMainInvocationStub_Base;
		mov ulInvocationStubSize, eax;
		pop eax;
	}
	
	void* pRemoteInvocationStub = VirtualAllocEx(hProcess, 0, ulInvocationStubSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if(!pRemoteInvocationStub)
		throw Exception("Error allocating memory for remote dllmain invocation stub.");

	if(!WriteProcessMemory(hProcess, pRemoteInvocationStub, pInvocationStubBase, ulInvocationStubSize, 0))
		throw Exception("Error copying dllmain invocation stub into remote process.");

	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pRemoteInvocationStub), (void*)pLibraryBase, 0, 0);

	if(WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
		throw Exception("Error waiting for remote thread on dllmain invocation stub.");

	if(!VirtualFreeEx(hProcess, pRemoteInvocationStub, 0, MEM_RELEASE))
		throw Exception("Error freeing dllmain invocation stub.");

	CloseHandle(hThread);
	return reinterpret_cast<HMODULE>(pLibraryBase);
}

HMODULE PeLoader::loadLibrary(const std::string& sLibraryName, const HANDLE hProcess)
{
	//Is the library already loaded?
	HMODULE remoteLibrary = getLibrary(hProcess, sLibraryName);
	if(remoteLibrary)
		return remoteLibrary;

	PeLoader lib(sLibraryName);
	return lib.mapLibrary(hProcess);
}

HMODULE PeLoader::loadMemoryLibrary(const void* pSourceImage, const std::string& sLibraryName, const HANDLE hProcess)
{
	//Is the library already loaded?
	HMODULE remoteLibrary = getLibrary(hProcess, sLibraryName);
	if(remoteLibrary)
		return remoteLibrary;

	PeLoader lib(pSourceImage);
	return lib.mapLibrary(hProcess);
}