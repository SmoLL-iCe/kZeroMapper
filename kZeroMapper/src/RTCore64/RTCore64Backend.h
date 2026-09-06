#pragma once
#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_RTCORE64)

#include "../Common/KernelRwCallBackend.h"

class RTCore64Backend final : public KernelRwCallBackend
{
public:
	RTCore64Backend( )
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
	struct MemoryOperation
	{
		uint8_t gap1[ 8 ];
		uint64_t address;
		uint8_t gap2[ 4 ];
		uint32_t offset;
		uint32_t size;
		uint32_t data;
		uint8_t gap3[ 16 ];
	};

	bool ReadPrimitive( uint64_t address, uint32_t size, uint32_t* value );
	bool WritePrimitive( uint64_t address, uint32_t size, uint32_t value );
};




#endif // KZEROMAPPER_ENABLE_RTCORE64
