#include "MapperUtils.h"

std::vector<uint8_t> Tools::DecodePEBuffer(uint8_t* pBuffer, size_t size)
{
	std::vector<uint8_t> buffer{};
	if (!pBuffer || size == 0)
		return buffer;

	buffer.insert(buffer.end(), pBuffer, pBuffer + size);

	for (size_t i = 0; i < size; i++)
	{
		buffer[i] = static_cast<uint8_t>(buffer[i] ^ static_cast<uint8_t>(i + 100));
	}

	return buffer;
}

bool Tools::EnableDebugPrivilege(const bool b_enable)
{
	auto result = false;
	HANDLE h_token = nullptr;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &h_token))
	{
		TOKEN_PRIVILEGES tp{};
		tp.PrivilegeCount = 1;

		LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = b_enable ? SE_PRIVILEGE_ENABLED : 0;

		AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
		result = (GetLastError() == ERROR_SUCCESS);

		CloseHandle(h_token);
	}
	return result;
}
