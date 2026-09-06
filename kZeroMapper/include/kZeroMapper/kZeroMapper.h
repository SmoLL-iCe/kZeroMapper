#pragma once

#ifndef WIN32_NO_STATUS
#define KZEROMAPPER_DEFINED_WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

#include <Windows.h>

#ifdef KZEROMAPPER_DEFINED_WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#undef KZEROMAPPER_DEFINED_WIN32_NO_STATUS
#endif

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)

#include <cstdint>
#include <cstddef>
#include "kZeroMapperConfig.h"
#include "MapperTypes.h"
#include "MapperStatus.h"

bool StopDriverService( const wchar_t* serviceName, bool bDelete = false );

namespace kZeroMapper {
	using LogCallback = void(*)(const char* message);
	void SetLogCallback(LogCallback callback);

	NTSTATUS MapDriver(void* pDrvData = nullptr, size_t szDataSize = 0, bool bClean = false);
	NTSTATUS MapDriver(MapperProvider provider, void* pDrvData = nullptr, size_t szDataSize = 0, KernelAllocationMode allocationMode = KernelAllocationMode::Pool, bool bClean = false);
	bool IsProviderSupported(MapperProvider provider);
	NTSTATUS GetLastStatus();
	NTSTATUS GetStatus2();
	using ::StopDriverService;
}

namespace KernelMapper = kZeroMapper;

#pragma comment(lib, "kZeroMapper.lib")
