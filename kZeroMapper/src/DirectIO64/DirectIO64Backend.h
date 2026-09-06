#pragma once
#include "../Common/KernelRwCallBackend.h"

class DirectIO64Backend final : public KernelRwCallBackend
{
public:
	std::string Name( ) const override;

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
	static bool PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress );
	bool VirtualToPhysical( uint64_t virtualAddress, uint64_t* physicalAddress );
	bool ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write );
};
