#pragma once
#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_CORMEM)

#include "../Common/TableWalkBackend.h"

class CorMemBackend final : public TableWalkBackend
{
public:
	std::string Name( ) const override;

protected:
	NTSTATUS LoadDevice( ) override;
	NTSTATUS UnloadDevice( ) override;
	bool ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint64_t bytes, bool write ) override;

private:
	bool MapPhysical( uint64_t physicalAddress, uint64_t size, uint64_t* virtualAddress );
	bool UnmapPhysical( uint64_t virtualAddress );
};




#endif // KZEROMAPPER_ENABLE_CORMEM