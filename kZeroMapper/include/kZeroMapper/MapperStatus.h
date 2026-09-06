#pragma once
#include <cstdint>

namespace kZeroMapper {


	enum class StatusCode : uint32_t {
		Success = 0,
		
		// Kernel Mapper Errors (KDMapper backend - base 0x9170)
		KDM_LoadFailed              = 0x9170,
		KDM_FailedWriteDriverFile   = 0x9171,
		KDM_FailedBuildDriverPath   = 0x9172,
		KDM_FailedOpenDevice        = 0x9173,
		KDM_DeviceAlreadyExists     = 0x9174,
		KDM_FailedStopExistingSvc   = 0x9175,
		KDM_NoOwningService         = 0x9177,
		KDM_FailedLoadVirtualDrv    = 0x9178,

		// General errors
		KM_GeneralFailure           = 0x9180,
		KM_ProviderNotSupported     = 0x9181,
	};
}

namespace KernelMapper = kZeroMapper;
