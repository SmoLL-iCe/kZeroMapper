#include "vDriverLoader.h"
#include <algorithm>
#include <string>
#include <vector>

namespace kZeroMapper
{
	const char* GetVulnerableDriverFileName( );
}

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

static void ResolveDriverNames( const char* backendName, const char* serviceName, std::string& outServiceName, std::string& outDriverFileName )
{
	std::string name;

	if ( serviceName && *serviceName )
	{
		name = serviceName;
	}
	else
	{
		const auto customName = kZeroMapper::GetVulnerableDriverFileName( );
		if ( customName && *customName )
			name = customName;
	}

	// Strip directory path if present
	const auto lastSlash = name.find_last_of( "\\/" );
	if ( lastSlash != std::string::npos )
		name = name.substr( lastSlash + 1 );

	// Strip whitespace
	while ( !name.empty( ) && ( name.front( ) == ' ' || name.front( ) == '\t' ) )
		name.erase( name.begin( ) );
	while ( !name.empty( ) && ( name.back( ) == ' ' || name.back( ) == '\t' || name.back( ) == '\r' || name.back( ) == '\n' ) )
		name.pop_back( );

	// Strip trailing ".sys" for service name
	if ( name.size( ) > 4 && _stricmp( name.c_str( ) + name.size( ) - 4, ".sys" ) == 0 )
		name.resize( name.size( ) - 4 );

	// If name became empty, fallback to backendName or "VirtualDrv"
	if ( name.empty( ) )
	{
		if ( backendName && *backendName )
			name = backendName;
		else
			name = "VirtualDrv";
	}

	outServiceName = name;
	outDriverFileName = name + pstra( ".sys" );
}

bool BuildMapperDriverPathW( wchar_t* buffer, size_t count, const wchar_t* driverFileName )
{
	if ( !buffer || !count || !driverFileName || !*driverFileName )
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
	if ( !buffer || !count || !driverFileName || !*driverFileName )
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
	std::string svcName, drvFileName;
	ResolveDriverNames( nullptr, nullptr, svcName, drvFileName );
	const std::wstring wDrvFileName( drvFileName.begin( ), drvFileName.end( ) );
	return BuildMapperDriverPathW( buffer, count, wDrvFileName.c_str( ) );
}

bool BuildMapperDriverPathA( char* buffer, size_t count )
{
	std::string svcName, drvFileName;
	ResolveDriverNames( nullptr, nullptr, svcName, drvFileName );
	return BuildMapperDriverPathA( buffer, count, drvFileName.c_str( ) );
}

static bool WriteDriverToDisk( const wchar_t* filePath, const void* buffer, size_t size, DWORD* outWritten, DWORD* outGle )
{
	if ( outWritten )
		*outWritten = 0;
	if ( outGle )
		*outGle = ERROR_SUCCESS;

	if ( !filePath || !*filePath || !buffer || !size )
	{
		if ( outGle )
			*outGle = ERROR_INVALID_PARAMETER;
		return false;
	}

	const auto pathLen = wcslen( filePath );
	if ( filePath[ pathLen - 1 ] == L'\\' || filePath[ pathLen - 1 ] == L'/' )
	{
		if ( outGle )
			*outGle = ERROR_BAD_PATHNAME;
		return false;
	}

	// Remove read-only or hidden attributes from previous runs
	SetFileAttributesW( filePath, FILE_ATTRIBUTE_NORMAL );

	HANDLE hFile = CreateFileW(
		filePath,
		GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if ( hFile == INVALID_HANDLE_VALUE )
	{
		const DWORD initialGle = GetLastError( );
		DeleteFileW( filePath );
		Sleep( 50 );

		hFile = CreateFileW(
			filePath,
			GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);

		if ( hFile == INVALID_HANDLE_VALUE )
		{
			if ( outGle )
				*outGle = ( GetLastError( ) != ERROR_SUCCESS ) ? GetLastError( ) : initialGle;
			return false;
		}
	}

	SetFilePointer( hFile, 0, nullptr, FILE_BEGIN );

	DWORD totalWritten = 0;
	const auto pBytes = static_cast<const uint8_t*>( buffer );

	while ( totalWritten < size )
	{
		const auto toWrite = static_cast<DWORD>( std::min<size_t>( size - totalWritten, 0x100000 ) );
		DWORD chunkWritten = 0;

		if ( !WriteFile( hFile, pBytes + totalWritten, toWrite, &chunkWritten, nullptr ) || chunkWritten == 0 )
		{
			if ( outGle )
				*outGle = GetLastError( );
			if ( outWritten )
				*outWritten = totalWritten;
			CloseHandle( hFile );
			return false;
		}

		totalWritten += chunkWritten;
	}

	FlushFileBuffers( hFile );
	CloseHandle( hFile );

	if ( outWritten )
		*outWritten = totalWritten;

	return totalWritten == size;
}

NTSTATUS DropLoadAndOpenMapperDriver( const char* backendName, const wchar_t* devicePath, const void* driverData, size_t driverSize, HANDLE* deviceHandle, uint32_t statusBase, const char* serviceName )
{
	if ( !backendName || !devicePath || !driverData || !driverSize || !deviceHandle )
		return STATUS_INVALID_PARAMETER;

	*deviceHandle = INVALID_HANDLE_VALUE;

	std::string ansiServiceName;
	std::string ansiDriverFileName;
	ResolveDriverNames( backendName, serviceName, ansiServiceName, ansiDriverFileName );

	const std::wstring wDriverFileNameSuffix( ansiDriverFileName.begin( ), ansiDriverFileName.end( ) );

	wchar_t wDrvFileName[ MAX_PATH * 2 ]{};

	if ( !BuildMapperDriverPathW( wDrvFileName, _countof( wDrvFileName ), wDriverFileNameSuffix.c_str( ) ) )
	{
		LOG_SEC( "[-] - [%s] Ldr: BuildMapperDriverPathW failed for file=%ls", backendName, wDriverFileNameSuffix.c_str( ) );
		return statusBase;
	}

	DWORD written = 0;
	DWORD gle = 0;

	if ( !WriteDriverToDisk( wDrvFileName, driverData, driverSize, &written, &gle ) )
	{
		LOG_SEC( "[-] - [%s] Ldr: Error writing driver on disk written=0x%X expected=0x%llx gle=%lu file=%ls", backendName, written, driverSize, gle, wDrvFileName );
		return statusBase + 1;
	}

	char drvFileName[ MAX_PATH ]{};

	if ( !BuildMapperDriverPathA( drvFileName, _countof( drvFileName ), ansiDriverFileName.c_str( ) ) )
	{
		LOG_SEC( "[-] - [%s] Ldr: BuildMapperDriverPathA failed for file=%s", backendName, ansiDriverFileName.c_str( ) );
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
		LOG_SEC( "[-] - [%s] SCM: Driver device open failure gle=%lu path=%ls", backendName, GetLastError( ), devicePath );
		UnloadMapperDriver( ansiServiceName.c_str( ) );
		return statusBase + 3;
	}

	LOG_SEC( "[!] - [%s] SCM: V. driver loaded as %s and opened", backendName, ansiServiceName.c_str( ) );
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
	std::string ansiServiceName;
	std::string ansiDriverFileName;
	ResolveDriverNames( nullptr, serviceName, ansiServiceName, ansiDriverFileName );

	char drvFileName[ MAX_PATH ]{};

	if ( BuildMapperDriverPathA( drvFileName, _countof( drvFileName ), ansiDriverFileName.c_str( ) ) )
	{
		return LoadAndUnload( ansiServiceName.c_str( ), drvFileName, false, false );
	}

	return STATUS_UNSUCCESSFUL;
}
