#pragma once
#include "../Common/KernelRwCallBackend.h"

class RTCore64Backend final : public KernelRwCallBackend
{
public:
	std::string Name( ) const override;
	NTSTATUS Load( ) override;

protected:
	NTSTATUS LoadDevice( ) override;
	NTSTATUS UnloadDevice( ) override;
	bool ReadMemory( uint64_t address, void* buffer, size_t size ) override;
	bool WriteMemory( uint64_t address, const void* buffer, size_t size ) override;
	bool PrepareKernelCall( uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize ) override;
	bool RestoreKernelCall( uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize ) override;

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
	uint64_t ResolveNtUserSetGestureConfigRef( );
	uint64_t ResolveNtUserSetGestureConfigRefFromSessionState( uint64_t win32k, uint64_t ntUserSetGestureConfigFull );

	uint64_t m_NtUserSetGestureConfigRef = 0;
};
