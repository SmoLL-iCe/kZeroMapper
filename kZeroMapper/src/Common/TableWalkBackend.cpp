#include "TableWalkBackend.h"
#include "../DirectIO64/halamd64.h"
#include <algorithm>
#include <vector>

namespace
{
	constexpr uint64_t PhysicalAddressMask           = 0x000ffffffffff000ull;
	constexpr uint64_t PhysicalAddressMask2MbPages   = 0x000fffffffe00000ull;
	constexpr uint64_t PhysicalAddressMask1GbPages   = 0x000fffffc0000000ull;
	constexpr uint64_t VirtualAddressMask2MbPages    = 0x00000000001fffffull;
	constexpr uint64_t VirtualAddressMask1GbPages    = 0x000000003fffffffull;
	constexpr uint64_t VirtualAddressMask4KbPages    = 0x0000000000000fffull;
	constexpr uint64_t EntryPageSizeBit              = 0x0000000000000080ull;
	constexpr uint64_t EntryPresentBit               = 0x0000000000000001ull;
	constexpr uint64_t MaxValidPhysicalAddress       = 0x10000000000ull;

	ULONG GetProcessorStartBlockCr3Offset( )
	{
		return FIELD_OFFSET( PROCESSOR_START_BLOCK, ProcessorState ) +
			FIELD_OFFSET( KSPECIAL_REGISTERS, Cr3 );
	}

	ULONG ScanLowStubForPml4( const uint8_t* data, ULONG size )
	{
		const auto cr3Offset = GetProcessorStartBlockCr3Offset( );
		const auto lmTargetOffset = FIELD_OFFSET( PROCESSOR_START_BLOCK, LmTarget );

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
				if ( !cr3Page || cr3Page >= MaxValidPhysicalAddress )
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

	bool SafeMemcpyShared( void* dst, const void* src, size_t size )
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

	struct QuietGuardShared
	{
		bool& m_Flag;
		explicit QuietGuardShared( bool& flag ) : m_Flag( flag ) { m_Flag = true; }
		~QuietGuardShared( ) { m_Flag = false; }
	};
}

ULONG TableWalkBackend::GetLowMemoryChunkSize( ) const
{
	return 0x1000000;
}

bool TableWalkBackend::ValidateCr3WithNtoskrnl( uint64_t cr3 )
{
	if ( !m_Ntoskrnl )
		return false;

	uint64_t testPa = 0;
	if ( !VirtualToPhysicalWithCr3( cr3, m_Ntoskrnl, &testPa ) )
		return false;

	if ( testPa == 0 || testPa >= MaxValidPhysicalAddress )
		return false;

	uint16_t mz = 0;
	if ( !ReadWritePhysical( testPa, &mz, sizeof( mz ), false ) )
		return false;

	return mz == 0x5A4D;
}

bool TableWalkBackend::QueryPml4( uint64_t* value )
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
	const ULONG chunkSize = GetLowMemoryChunkSize( );
	std::vector<uint8_t> lowMemory( mapSize );

	bool readOk = true;

	for ( ULONG chunkOffset = 0; chunkOffset < mapSize && readOk; chunkOffset += chunkSize )
	{
		const auto currentChunk = std::min<ULONG>( chunkSize, mapSize - chunkOffset );

		if ( !ReadWritePhysical( chunkOffset, lowMemory.data( ) + chunkOffset, currentChunk, false ) )
		{
			LOG_SEC( "[-] - [%s] QueryPml4 failed to read low chunk pa=0x%llx size=0x%X", Name( ).c_str( ), chunkOffset, currentChunk );
			readOk = false;
			break;
		}
	}

	if ( !readOk )
		return false;

	const auto stubOffset = ScanLowStubForPml4( lowMemory.data( ), mapSize );

	if ( stubOffset != 0xFFFFFFFF )
	{
		const auto cr3Offset = GetProcessorStartBlockCr3Offset( );
		const auto rawCr3 = *r_cast<const uint64_t*>( lowMemory.data( ) + stubOffset + cr3Offset );

		if ( ValidateCr3WithNtoskrnl( rawCr3 ) )
		{
			m_Pml4Cache = rawCr3;
			*value = rawCr3;
			LOG_SEC( "[*] - [%s] QueryPml4 validated pml4=0x%llx", Name( ).c_str( ), *value );
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
				LOG_SEC( "[*] - [%s] QueryPml4 KPTI kernel cr3=0x%llx (variant %d, user=0x%llx)",
					Name( ).c_str( ), *value, i, rawCr3 );
				return true;
			}
		}

		LOG_SEC( "[-] - [%s] Low stub CR3 and KPTI variants all failed validation", Name( ).c_str( ) );
	}

	LOG_SEC( "[*] - [%s] Scanning low 16MB for CR3 candidates", Name( ).c_str( ) );

	if ( !m_Ntoskrnl )
	{
		LOG_SEC( "[-] - [%s] No validation VA (ntoskrnl=0)", Name( ).c_str( ) );
		return false;
	}

	const auto p = r_cast<const uint64_t*>( lowMemory.data( ) );
	const size_t qwordCount = mapSize / sizeof( uint64_t );

	ULONG tested = 0;
	{
		QuietGuardShared guard( m_QuietMode );

		for ( size_t i = 0; i < qwordCount; ++i )
		{
			const auto candidate = p[ i ];

			if ( candidate == 0 || candidate == 0xFFFFFFFFFFFFFFFFull )
				continue;

			if ( ( candidate >> 52 ) != 0 )
				continue;

			const auto candidatePa = candidate & PhysicalAddressMask;
			if ( !candidatePa || candidatePa >= MaxValidPhysicalAddress )
				continue;

			if ( candidatePa < 0x1000 )
				continue;

			if ( !ValidateCr3WithNtoskrnl( candidate ) )
				continue;

			++tested;

			m_Pml4Cache = candidate;
			*value = candidate;
			LOG_SEC( "[*] - [%s] QueryPml4 found pml4=0x%llx at offset=0x%llx (tested=%lu)",
				Name( ).c_str( ), *value, i * 8, tested );
			return true;
		}
	}

	LOG_SEC( "[-] - [%s] QueryPml4 failed to find PML4 (tested=%lu candidates)", Name( ).c_str( ), tested );
	return false;
}

bool TableWalkBackend::PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress )
{
	if ( entry & EntryPresentBit )
	{
		*physicalAddress = entry & PhysicalAddressMask;
		return true;
	}

	return false;
}

bool TableWalkBackend::VirtualToPhysicalWithCr3( uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress )
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

bool TableWalkBackend::VirtualToPhysicalByTableWalk( uint64_t virtualAddress, uint64_t* physicalAddress )
{
	if ( !physicalAddress )
		return false;

	uint64_t pml4 = 0;

	if ( !QueryPml4( &pml4 ) )
	{
		LOG_SEC( "[-] - [%s] VirtualToPhysicalByTableWalk failed QueryPml4 va=0x%llx", Name( ).c_str( ), virtualAddress );
		return false;
	}

	if ( !VirtualToPhysicalWithCr3( pml4, virtualAddress, physicalAddress ) )
	{
		LOG_SEC( "[-] - [%s] VirtualToPhysicalByTableWalk failed va=0x%llx pml4=0x%llx", Name( ).c_str( ), virtualAddress, pml4 );
		return false;
	}

	return true;
}

bool TableWalkBackend::ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write )
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

bool TableWalkBackend::ReadMemory( uint64_t address, void* buffer, size_t size )
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

		LOG_SEC( "[*] - [%s] ReadMemory %zu/%zu pages paged out va=0x%llx (attempt %d)", Name( ).c_str( ), failed, ( size + 0xFFF ) / 0x1000, address, attempt + 1 );
	}

	return false;
}

bool TableWalkBackend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	const auto result = ReadWriteVirtual( address, const_cast<void*>( buffer ), size, true );

	if ( !result )
		LOG_SEC( "[-] - [%s] WriteMemory failed va=0x%llx size=0x%llx", Name( ).c_str( ), address, size );

	return result;
}