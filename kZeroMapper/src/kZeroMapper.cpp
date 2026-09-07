#include <kZeroMapper/kZeroMapper.h>
#include <kZeroMapper/kZeroMapperConfig.h>
#include "Common/MapperExecutor.h"
#include "Common/MapperLogging.h"


#if defined(KZEROMAPPER_ENABLE_DIRECTIO64)
#include "DirectIO64/DirectIO64Backend.h"
#endif

#if defined(KZEROMAPPER_ENABLE_KDMAPPER)
#include "KDMapper/KDMapperBackend.h"
#endif

#if defined(KZEROMAPPER_ENABLE_KKYUM)
#include "KKYUM/KKYUMBackend.h"
#endif

#if defined(KZEROMAPPER_ENABLE_PCDSRVC)
#include "PCDSRVC/PCDSRVCBackend.h"
#endif

#if defined(KZEROMAPPER_ENABLE_PPA64)
#include "PPA64/PPA64Backend.h"
#endif

#if defined(KZEROMAPPER_ENABLE_CORMEM)
#include "CorMem/CorMemBackend.h"
#endif

#if defined(KZEROMAPPER_ENABLE_WINIO64)
#include "WinIo64/WinIo64Backend.h"
#endif

#if defined(KZEROMAPPER_ENABLE_RTCORE64)
#include "RTCore64/RTCore64Backend.h"
#endif

#if defined(KZEROMAPPER_ENABLE_VIRTUALBOX)
#include "VirtualBox/VirtualBoxBackend.h"
#endif

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

#if defined(KZEROMAPPER_ENABLE_VIRTUALBOX)
	NTSTATUS RunVirtualBoxBackend( void* pDrvData, size_t szDataSize, bool bClean )
	{
		VirtualBoxBackend backend;
		const auto result = RunMapperBackend( backend, pDrvData, szDataSize, bClean );
		g_Status2 = backend.Status2( );
		return result;
	}
#endif
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

	bool IsProviderSupported( MapperProvider provider )
	{
		switch ( provider )
		{
		case MapperProvider::DirectIO64:
#if defined(KZEROMAPPER_ENABLE_DIRECTIO64)
			return true;
#else
			return false;
#endif
		case MapperProvider::KDMapper:
#if defined(KZEROMAPPER_ENABLE_KDMAPPER)
			return true;
#else
			return false;
#endif
		case MapperProvider::KKYUM:
#if defined(KZEROMAPPER_ENABLE_KKYUM)
			return true;
#else
			return false;
#endif
		case MapperProvider::PCDSRVC:
#if defined(KZEROMAPPER_ENABLE_PCDSRVC)
			return true;
#else
			return false;
#endif
		case MapperProvider::PPA64:
#if defined(KZEROMAPPER_ENABLE_PPA64)
			return true;
#else
			return false;
#endif
		case MapperProvider::CorMem:
#if defined(KZEROMAPPER_ENABLE_CORMEM)
			return true;
#else
			return false;
#endif
		case MapperProvider::WinIo64:
#if defined(KZEROMAPPER_ENABLE_WINIO64)
			return true;
#else
			return false;
#endif
		case MapperProvider::RTCore64:
#if defined(KZEROMAPPER_ENABLE_RTCORE64)
			return true;
#else
			return false;
#endif
		case MapperProvider::VirtualBox:
#if defined(KZEROMAPPER_ENABLE_VIRTUALBOX)
			return true;
#else
			return false;
#endif
		default:
			return false;
		}
	}

	NTSTATUS MapDriver( void* pDrvData, size_t szDataSize, bool bClean )
	{
		if ( GetBuildNumber( ) >= 26100 )
		{
#if defined(KZEROMAPPER_ENABLE_RTCORE64)
		return MapDriver( MapperProvider::RTCore64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_DIRECTIO64)
		return MapDriver( MapperProvider::DirectIO64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_PCDSRVC)
		return MapDriver( MapperProvider::PCDSRVC, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_PPA64)
		return MapDriver( MapperProvider::PPA64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_CORMEM)
		return MapDriver( MapperProvider::CorMem, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_WINIO64)
		return MapDriver( MapperProvider::WinIo64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_KKYUM)
		return MapDriver( MapperProvider::KKYUM, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_VIRTUALBOX)
		return MapDriver( MapperProvider::VirtualBox, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_KDMAPPER)
		return MapDriver( MapperProvider::KDMapper, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#else
		InternalLog( "[-] [kZeroMapper] No kernel backend available at compile time." );
		return static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
	}

#if defined(KZEROMAPPER_ENABLE_KDMAPPER)
	return MapDriver( MapperProvider::KDMapper, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_RTCORE64)
	return MapDriver( MapperProvider::RTCore64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_DIRECTIO64)
	return MapDriver( MapperProvider::DirectIO64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_PCDSRVC)
	return MapDriver( MapperProvider::PCDSRVC, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_PPA64)
	return MapDriver( MapperProvider::PPA64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_CORMEM)
	return MapDriver( MapperProvider::CorMem, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_WINIO64)
	return MapDriver( MapperProvider::WinIo64, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_KKYUM)
	return MapDriver( MapperProvider::KKYUM, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#elif defined(KZEROMAPPER_ENABLE_VIRTUALBOX)
	return MapDriver( MapperProvider::VirtualBox, pDrvData, szDataSize, KernelAllocationMode::Pool, bClean );
#else
	InternalLog( "[-] [kZeroMapper] No kernel backend available at compile time." );
	return static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
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
		{
#if defined(KZEROMAPPER_ENABLE_RTCORE64)
			result = RunKernelRwBackend<RTCore64Backend>( pDrvData, szDataSize, allocationMode, bClean );
#else
			InternalLog( "[-] [kZeroMapper] RTCore64 backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else if ( provider == MapperProvider::DirectIO64 )
		{
#if defined(KZEROMAPPER_ENABLE_DIRECTIO64)
			result = RunKernelRwBackend<DirectIO64Backend>( pDrvData, szDataSize, allocationMode, bClean );
#else
			InternalLog( "[-] [kZeroMapper] DirectIO64 backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else if ( provider == MapperProvider::PCDSRVC )
		{
#if defined(KZEROMAPPER_ENABLE_PCDSRVC)
			result = RunKernelRwBackend<PCDSRVCBackend>( pDrvData, szDataSize, allocationMode, bClean );
#else
			InternalLog( "[-] [kZeroMapper] PCDSRVC backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else if ( provider == MapperProvider::PPA64 )
		{
#if defined(KZEROMAPPER_ENABLE_PPA64)
			result = RunKernelRwBackend<PPA64Backend>( pDrvData, szDataSize, allocationMode, bClean );
#else
			InternalLog( "[-] [kZeroMapper] PPA64 backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else if ( provider == MapperProvider::CorMem )
		{
#if defined(KZEROMAPPER_ENABLE_CORMEM)
			result = RunKernelRwBackend<CorMemBackend>( pDrvData, szDataSize, allocationMode, bClean );
#else
			InternalLog( "[-] [kZeroMapper] CorMem backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else if ( provider == MapperProvider::WinIo64 )
		{
#if defined(KZEROMAPPER_ENABLE_WINIO64)
			result = RunKernelRwBackend<WinIo64Backend>( pDrvData, szDataSize, allocationMode, bClean );
#else
			InternalLog( "[-] [kZeroMapper] WinIo64 backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else if ( provider == MapperProvider::KKYUM )
		{
#if defined(KZEROMAPPER_ENABLE_KKYUM)
			result = RunKernelRwBackend<KKYUMBackend>( pDrvData, szDataSize, allocationMode, bClean );
#else
			InternalLog( "[-] [kZeroMapper] KKYUM backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else if ( provider == MapperProvider::KDMapper )
		{
#if defined(KZEROMAPPER_ENABLE_KDMAPPER)
			result = RunKernelRwBackend<KDMapperBackend>( pDrvData, szDataSize, allocationMode, bClean );
#else
			InternalLog( "[-] [kZeroMapper] KDMapper backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else if ( provider == MapperProvider::VirtualBox )
		{
#if defined(KZEROMAPPER_ENABLE_VIRTUALBOX)
			result = RunVirtualBoxBackend( pDrvData, szDataSize, bClean );
#else
			InternalLog( "[-] [kZeroMapper] VirtualBox backend is not enabled in build configuration." );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
#endif
		}
		else
		{
			InternalLog( "[-] [kZeroMapper] Provider not supported or invalid: %d", static_cast<int>( provider ) );
			result = static_cast<NTSTATUS>( StatusCode::KM_ProviderNotSupported );
		}

		g_LastStatus = result;
		return result;
	}
}
