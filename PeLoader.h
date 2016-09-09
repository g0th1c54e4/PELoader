//Author: Jetamay (Mpgh.Net)
//License: Do w\e you want w\ it, just do not distribute it in your own name, etc... Not that I will do anything if you do. I'll probably
//         be a little pissed off, but whatever.

#pragma once

#include <Windows.h>
#include <string>

#include "Exception.h"

namespace PeLoaderLib
{
	class PeLoader
	{
	private:

		std::string m_sLibraryName;

		HANDLE m_hFileMap;
		HANDLE m_hFile;
		void*  m_pFileView;

		IMAGE_NT_HEADERS* m_pFileNtHeaders;
		IMAGE_DOS_HEADER* m_pFileDosHeader;

		void init(const void* pView, const HANDLE hFile = 0, const HANDLE hFileMap = 0);

	protected:
		PeLoader(const std::string& sLibraryName);
		PeLoader(const void* pSourceImage);
		virtual ~PeLoader();

		static inline bool isValidNtHeaders(const IMAGE_NT_HEADERS* pNtHeaders);
		static inline bool isValidDosHeader(const IMAGE_DOS_HEADER* pDosHeader);

		static void calculateRelocation(const HANDLE hProc, const long difference, const unsigned long ulBase, const WORD wOffset);
		static void setSectionPermissions(const HANDLE hProc, const void* pAddress, const unsigned long ulSize, const unsigned long ulCharacteristics);

		static HMODULE getLibrary(const HANDLE hProc, const std::string& sLibraryName);
		static void*   getRemoteProcAddress(const HANDLE hProc, const HMODULE hModule, const char* sProcName);

		static const IMAGE_SECTION_HEADER* getRvaSection(const unsigned long ulRva, const IMAGE_NT_HEADERS* pNtHeaders);
		static long	 rvaToFileOffset(const unsigned long ulRva, const IMAGE_NT_HEADERS* pNtHeaders);
		
		static HMODULE PeLoader::remoteLoadLibrary(const HANDLE hProc, const char* sLibraryName);
		HMODULE mapLibrary(const HANDLE hProcess);

	public:

		static HMODULE loadLibrary(const std::string& sLibraryName, const HANDLE hProcess = GetCurrentProcess());
		static HMODULE loadMemoryLibrary(const void* pSourceImage, const std::string& sLibraryName = std::string(), const HANDLE hProcess = GetCurrentProcess());
	};
};