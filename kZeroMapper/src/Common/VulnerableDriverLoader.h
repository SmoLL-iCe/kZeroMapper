#pragma once
#include "MapperBackend.h"

bool BuildMapperDriverPathW( wchar_t* buffer, size_t count );
bool BuildMapperDriverPathA( char* buffer, size_t count );
bool BuildMapperDriverPathW( wchar_t* buffer, size_t count, const wchar_t* driverFileName );
bool BuildMapperDriverPathA( char* buffer, size_t count, const char* driverFileName );
NTSTATUS DropLoadAndOpenMapperDriver( const char* backendName, const wchar_t* devicePath, const void* driverData, size_t driverSize, HANDLE* deviceHandle, uint32_t statusBase, const char* serviceName = nullptr );
void CloseMapperDevice( HANDLE* deviceHandle );
NTSTATUS UnloadMapperDriver( const char* serviceName = nullptr );
bool IsObjExist( const wchar_t* RootDir, const wchar_t* objName );
bool StopDriverService( const wchar_t* serviceName, bool bDelete = false );
