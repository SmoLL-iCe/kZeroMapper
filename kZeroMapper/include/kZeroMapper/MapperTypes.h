#pragma once
#include <cstdint>

namespace kZeroMapper {


	enum class KernelAllocationMode : uint32_t
	{
		Pool,
		IndependentPages
	};

	enum class MapperProvider
	{
		VirtualBox,
		RTCore64,
		DirectIO64,
		PCDSRVC,
		PPA64,
		CorMem,
		WinIo64,
		KKYUM,
		KDMapper,
		Auto
	};
}

namespace KernelMapper = kZeroMapper;
