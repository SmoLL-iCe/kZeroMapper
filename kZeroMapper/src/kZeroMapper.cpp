#include <kZeroMapper/kZeroMapper.h>
#include "Common/MapperExecutor.h"
#include "Common/MapperLogging.h"
#include "CPUZ/CPUZBackend.h"
#include "DirectIO64/DirectIO64Backend.h"
#include "KDMapper/KDMapperBackend.h"
#include "KKYUM/KKYUMBackend.h"
#include "RTCore64/RTCore64Backend.h"
#include "VirtualBox/VirtualBoxBackend.h"

namespace
{
	NTSTATUS g_LastStatus = 0;
	NTSTATUS g_Status2 = 0;
	kZeroMapper::LogCallback g_LogCallback = nullptr;

	template<typename TBackend>
	NTSTATUS RunKernelRwBackend( void* pDrvData, size_t szDataSize, KernelAllocationMode allocationMode, bool bClean )
	{
		TBackend backend{};
		backend.SetAllocationMode( allocationMode );
		return RunMapperBackend( backend, pDrvData, szDataSize, bClean );
	}

	NTSTATUS RunVirtualBoxBackend( void* pDrvData, size_t szDataSize, bool bClean )
	{
		VirtualBoxBackend backend;
		const auto result = RunMapperBackend( backend, pDrvData, szDataSize, bClean );
		g_Status2 = backend.Status2( );
		return result;
	}
}

namespace kZeroMapper
{
	void InternalLog( const char* fmt, ... )
	{
		char buffer[ 1024 ];
		va_list args;
		va_start( args, fmt );
		vsnprintf( buffer, sizeof( buffer ), fmt, args );
		va_end( args );

		if ( g_LogCallback )
		{
			g_LogCallback( buffer );
		}
#if defined(_DEBUG) || defined(DEBUG)
		OutputDebugStringA( buffer );
		OutputDebugStringA( "\n" );
#endif
	}

	void SetLogCallback( LogCallback callback )
	{
		g_LogCallback = callback;
	}

	NTSTATUS GetLastStatus( )
	{
		return g_LastStatus;
	}

	NTSTATUS GetStatus2( )
	{
		return g_Status2;
	}

	NTSTATUS MapDriver( void* pDrvData, size_t szDataSize, bool bClean )
	{
		if ( GetBuildNumber( ) >= 26100 )
			return MapDriver( MapperProvider::RTCore64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );

		return MapDriver( MapperProvider::KDMapper, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
	}

	NTSTATUS MapDriver( MapperProvider provider, void* pDrvData, size_t szDataSize, KernelAllocationMode allocationMode, bool bClean )
	{
		g_LastStatus = 0;
		g_Status2 = 0;

		const auto initStatus = InitializeMapperRuntime( );
		if ( initStatus != STATUS_SUCCESS )
		{
			g_LastStatus = initStatus;
			return initStatus;
		}

		NTSTATUS result = STATUS_UNSUCCESSFUL;

		if ( provider == MapperProvider::RTCore64 )
			result = RunKernelRwBackend<RTCore64Backend>( pDrvData, szDataSize, allocationMode, bClean );
		else if ( provider == MapperProvider::DirectIO64 )
			result = RunKernelRwBackend<DirectIO64Backend>( pDrvData, szDataSize, allocationMode, bClean );
		else if ( provider == MapperProvider::CPUZ )
			result = RunKernelRwBackend<CPUZBackend>( pDrvData, szDataSize, allocationMode, bClean );
		else if ( provider == MapperProvider::KKYUM )
			result = RunKernelRwBackend<KKYUMBackend>( pDrvData, szDataSize, allocationMode, bClean );
		else if ( provider == MapperProvider::KDMapper )
			result = RunKernelRwBackend<KDMapperBackend>( pDrvData, szDataSize, allocationMode, bClean );
		else if ( provider == MapperProvider::VirtualBox )
			result = RunVirtualBoxBackend( pDrvData, szDataSize, bClean );
		else
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );

		g_LastStatus = result;
		return result;
	}
}
