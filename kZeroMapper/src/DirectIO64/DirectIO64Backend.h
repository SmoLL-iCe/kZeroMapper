#pragma once
#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_DIRECTIO64)

#include "../Common/KernelRwCallBackend.h"

class DirectIO64Backend final : public KernelRwCallBackend
{
public:
	DirectIO64Backend( )
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
	#pragma pack(push, 1)
	struct PhysicalMemoryInfo
	{
		HANDLE SectionHandle;
		PVOID BaseAddressIoSpace;
		PVOID AllocatedMdl;
		DWORD ViewSize;
		LARGE_INTEGER Offset;
		PVOID BaseAddress;
		BOOLEAN Writeable;
	};
	#pragma pack(pop)

	bool CallDriver( ULONG ioControlCode, PVOID inputBuffer, ULONG inputLength, PVOID outputBuffer, ULONG outputLength );
	PVOID MapPhysicalMemory( uint64_t physicalAddress, ULONG bytes, HANDLE* sectionHandle, PVOID* allocatedMdl, BOOLEAN writable );
	void UnmapPhysicalMemory( PVOID sectionToUnmap, HANDLE sectionHandle, PVOID allocatedMdl );
	bool ReadWritePhysical( uint64_t physicalAddress, void* buffer, ULONG bytes, bool write );
	bool QueryPml4( uint64_t* value );
	bool ValidateCr3WithNtoskrnl( uint64_t cr3 );
	static bool PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress );
	bool VirtualToPhysicalWithCr3( uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress );
	bool VirtualToPhysical( uint64_t virtualAddress, uint64_t* physicalAddress );
	bool ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write );

	uint64_t m_Pml4Cache = 0;
	bool m_QuietMode = false;
};




#endif // KZEROMAPPER_ENABLE_DIRECTIO64
