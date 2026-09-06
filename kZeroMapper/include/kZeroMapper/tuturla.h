#pragma once
#include "kZeroMapper.h"

namespace vBox {
	using MapperProvider = kZeroMapper::MapperProvider;
	using KernelAllocationMode = kZeroMapper::KernelAllocationMode;

	inline NTSTATUS StartExploit(void* pDrvData = nullptr, size_t szDataSize = 0, bool bClean = false)
	{
		return kZeroMapper::MapDriver(pDrvData, szDataSize, bClean);
	}

	inline NTSTATUS StartExploit(MapperProvider provider, void* pDrvData = nullptr, size_t szDataSize = 0, KernelAllocationMode allocationMode = KernelAllocationMode::Pool, bool bClean = false)
	{
		return kZeroMapper::MapDriver(provider, pDrvData, szDataSize, allocationMode, bClean);
	}

	inline NTSTATUS GetStatus2()
	{
		return kZeroMapper::GetStatus2();
	}
}
