//Author: Jeremy

#include "stdafx.h"
#include <iostream>
#include <stdio.h>

#include "Exception.h"
#include "PeLoader.h"

using namespace PeLoaderLib;

int _tmain(int argc, _TCHAR* argv[])
{
    const char* const DLL_NAME = "testdll.dll";
    const unsigned long ulPid = 123;

    FILE* pFile = fopen(DLL_NAME, "rb");
    fseek(pFile, 0, SEEK_END);
    long sz = ftell(pFile);
    fseek(pFile, 0, SEEK_SET);

    void* pBuffer = new char[sz];

    for(unsigned long ulRead = 0; ulRead != sz;
        ulRead += fread(reinterpret_cast<void*>(reinterpret_cast<unsigned long>(pBuffer) + ulRead), 1, sz - ulRead, pFile));

    try
    {
        PeLoaderLib::PeLoader::loadMemoryLibrary(pBuffer, std::string(), OpenProcess(PROCESS_ALL_ACCESS, false, ulPid));
    }catch(const Exception& e)
    {
        std::cout<<"Error occured: "<<e.getReason()<<std::endl;
    }

    fclose(pFile);
}