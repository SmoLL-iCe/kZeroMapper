#pragma once

#include <cstdint>
#include <string>

#ifndef WIN32_NO_STATUS
#define MAPPER_DEFINED_WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

#include <Windows.h>

#ifdef MAPPER_DEFINED_WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#undef MAPPER_DEFINED_WIN32_NO_STATUS
#endif

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)

#include "ntos.h"
#include "MapperSecurity.h"
#include "MapperLogging.h"
#include "MapperUtils.h"
#include <kZeroMapper/MapperTypes.h>

#ifndef r_cast
#define r_cast reinterpret_cast
#endif

#ifndef s_cast
#define s_cast static_cast
#endif

using KernelAllocationMode = kZeroMapper::KernelAllocationMode;

class IMapperBackend
{
public:
	virtual ~IMapperBackend( ) = default;
	virtual std::string Name( ) const = 0;
	virtual NTSTATUS Load( ) = 0;
	virtual NTSTATUS Unload( ) = 0;
	virtual NTSTATUS Execute( uint8_t* shellCode, uint32_t codeSize ) = 0;
	virtual bool Clean( ) = 0;
};

void* GetSysInfo( SYSTEM_INFORMATION_CLASS InfoClass );
uint32_t WriteBufferToFile( PWSTR FileName, void* pBuffer, int Size, bool Flush, bool Append );
NTSTATUS LoadAndUnload( const char* strDrvName, const char* strDrvPath, bool load, bool vmInstalled );
ULONG GetBuildNumber( );
