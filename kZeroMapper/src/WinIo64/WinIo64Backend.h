#pragma once
#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_WINIO64)

#include "../Common/TableWalkBackend.h"

class WinIo64Backend final : public TableWalkBackend
{
public:
	std::string Name( ) const override;

protected:
	NTSTATUS LoadDevice( ) override;
	NTSTATUS UnloadDevice( ) override;
	ULONG GetLowMemoryChunkSize( ) const override;
	bool ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint64_t bytes, bool write ) override;

private:
	#pragma pack(push, 1)
	struct WinIoMapRequest
	{
		uint64_t Size;             // offset 0x00: bytes to map
		uint64_t PhysicalAddress;  // offset 0x08
		uint64_t Handle;           // offset 0x10: out, section handle (driver)
		uint64_t LinearAddress;    // offset 0x18: out, mapped VA (driver)
		uint64_t SectionObject;    // offset 0x20: out, section object (driver)
	};
	#pragma pack(pop)

	bool MapPhysical( uint64_t physicalAddress, uint64_t size, uint64_t* virtualAddress );
	bool UnmapPhysical( uint64_t virtualAddress );
};




#endif // KZEROMAPPER_ENABLE_WINIO64