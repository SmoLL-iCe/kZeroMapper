#pragma once
#include <Windows.h>
#include <vector>
#include <cstdint>

namespace Tools
{
	std::vector<uint8_t> DecodePEBuffer(uint8_t* pBuffer, size_t size);
	bool EnableDebugPrivilege(bool b_enable);
}
