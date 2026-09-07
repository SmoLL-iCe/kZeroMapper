#pragma once
#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_CORMEM)

#include "../Common/KernelRwCallBackend.h"

class CorMemBackend final : public KernelRwCallBackend
{
public:
	CorMemBackend( )
	{
		m_CallGate = KernelCallGate::TableSwap;
	}

	std::string Name( ) const override;
	NTSTATUS Load( ) override;

protected:
	NTSTATUS LoadDevice( ) override;
	NTSTATUS UnloadDevice( ) override;
	bool ReadMemory( uint64_t address, void* buffer, size_t size ) override;
	bool WriteMemory( uint64_t address, const void* buffer, size_t size ) override;

private:
	bool MapPhysical( uint64_t physicalAddress, uint64_t size, uint64_t* virtualAddress );
	bool UnmapPhysical( uint64_t virtualAddress );
	bool ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint64_t bytes, bool write );

	bool QueryPml4( uint64_t* value );
	bool ValidateCr3WithNtoskrnl( uint64_t cr3 );
	static bool PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress );
	bool VirtualToPhysicalWithCr3( uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress );
	bool VirtualToPhysicalByTableWalk( uint64_t virtualAddress, uint64_t* physicalAddress );
	bool ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write );

	uint64_t m_Pml4Cache = 0;
	bool m_QuietMode = false;
};




#endif // KZEROMAPPER_ENABLE_CORMEM