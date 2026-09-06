#pragma once
#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_CPUZ)

#include "../Common/KernelRwCallBackend.h"

class CPUZBackend final : public KernelRwCallBackend
{
public:
	CPUZBackend( )
	{
		m_CallGate = KernelCallGate::NtQueryAtom;
	}

	std::string Name( ) const override;

protected:
	NTSTATUS LoadDevice( ) override;
	NTSTATUS UnloadDevice( ) override;
	bool ReadMemory( uint64_t address, void* buffer, size_t size ) override;
	bool WriteMemory( uint64_t address, const void* buffer, size_t size ) override;
	bool WriteToReadOnlyMemory( uint64_t address, const void* buffer, size_t size ) override;

private:
	#pragma pack(push, 1)
	struct PhysicalMemoryRequest
	{
		union
		{
			struct
			{
				ULONG AddressHigh;
				ULONG AddressLow;
			};
			uint64_t Address;
		};
		ULONG Length;
		union
		{
			struct
			{
				ULONG BufferHigh;
				ULONG BufferLow;
			};
			uint64_t Buffer;
		};
	};
	#pragma pack(pop)

	bool AcquirePrivilege( ULONG privilege );
	bool ReadPhysicalMemory( uint64_t physicalAddress, void* buffer, size_t size );
	bool WriteVirtualMemory( uint64_t virtualAddress, const void* buffer, size_t size );
	bool QueryPml4( uint64_t* value );
	static bool PageEntryToPhysicalAddress( uint64_t entry, uint64_t* physicalAddress );
	bool VirtualToPhysical( uint64_t virtualAddress, uint64_t* physicalAddress );
	bool ReadVirtualMemory( uint64_t address, void* buffer, size_t size );

	uint64_t m_Pml4 = 0;
};




#endif // KZEROMAPPER_ENABLE_CPUZ
