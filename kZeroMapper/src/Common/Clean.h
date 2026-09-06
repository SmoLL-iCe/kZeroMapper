#pragma once
#include "KernelRwCallBackend.h"

class KernelClean
{
public:
	static constexpr ULONG32 IntelDriverTimestamp = 0x5284EAC3;

	static std::uint32_t ClearPiDDBCacheTable( KernelRwCallBackend& backend );
	static std::uint32_t ClearPiDDBCacheTableManual( KernelRwCallBackend& backend );
	static std::uint32_t ClearKernelHashBucketList( KernelRwCallBackend& backend );
	static std::uint32_t ClearMmUnloadedDrivers( KernelRwCallBackend& backend );
	static std::uint32_t ClearWdFilterDriverList( KernelRwCallBackend& backend );
	static bool RunAllCleanups( KernelRwCallBackend& backend );
};