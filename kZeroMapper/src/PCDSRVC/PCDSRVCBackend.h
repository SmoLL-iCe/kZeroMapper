#pragma once
#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_PCDSRVC)

#include "../Common/TableWalkBackend.h"

class PCDSRVCBackend final : public TableWalkBackend
{
public:
	std::string Name( ) const override;

protected:
	NTSTATUS LoadDevice( ) override;
	NTSTATUS UnloadDevice( ) override;
	bool ReadWritePhysical( uint64_t physicalAddress, void* buffer, uint64_t bytes, bool write ) override;

private:
	#pragma pack(push, 1)
	struct PhysicalMemoryHeader
	{
		uint64_t PhysicalAddress;
		uint32_t Length;
		uint8_t  AccessMode;
	};

	struct MsrAccess
	{
		uint32_t MsrRegister;
		uint64_t Value;
	};
	#pragma pack(pop)

	bool UnlockDriver( );
	bool GetPhysicalAddress( uint64_t virtualAddress, uint64_t* physicalAddress );
	bool ReadPhysical( uint64_t physicalAddress, void* buffer, uint32_t length );
	bool WritePhysical( uint64_t physicalAddress, const void* buffer, uint32_t length );
	bool ReadMsr( uint32_t msrRegister, uint64_t* value );
	bool WriteMsr( uint32_t msrRegister, uint64_t value );

	bool ReadWriteVirtual( uint64_t address, void* buffer, size_t size, bool write ) override;

	bool m_Unlocked = false;
};




#endif // KZEROMAPPER_ENABLE_PCDSRVC