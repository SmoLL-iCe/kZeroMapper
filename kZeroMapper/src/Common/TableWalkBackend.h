#pragma once
#include "KernelRwCallBackend.h"

// Shared CR3 discovery + x64 page-table walk machinery for backends that
// provide a physical-memory read/write primitive (via section mapping).
class TableWalkBackend : public KernelRwCallBackend
{
public:
	TableWalkBackend( )
	{
		m_CallGate = KernelCallGate::NtQueryAtom;
	}

protected:
	// Driver-specific physical memory primitive; handles map/copy/unmap internally.
	virtual bool ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint64_t bytes, bool write ) = 0;

	// Max bytes per map when snapshotting low memory (driver resource limits).
	virtual ULONG GetLowMemoryChunkSize( ) const;

	bool QueryPml4( uint64_t* value );
	bool ValidateCr3WithNtoskrnl( uint64_t cr3 );
	static bool PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress );
	bool VirtualToPhysicalWithCr3( uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress );
	virtual bool VirtualToPhysicalByTableWalk( uint64_t virtualAddress, uint64_t* physicalAddress );
	virtual bool ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write );

	bool ReadMemory( uint64_t address, void* buffer, size_t size ) override;
	bool WriteMemory( uint64_t address, const void* buffer, size_t size ) override;

	uint64_t m_Pml4Cache = 0;
	bool m_QuietMode = false;
};



