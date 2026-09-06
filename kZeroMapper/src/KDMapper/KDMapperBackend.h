#pragma once
#include "../Common/KernelRwCallBackend.h"

class KDMapperBackend final : public KernelRwCallBackend
{
public:
	std::string Name( ) const override;

protected:
	NTSTATUS LoadDevice( ) override;
	NTSTATUS UnloadDevice( ) override;
	bool ReadMemory( uint64_t address, void* buffer, size_t size ) override;
	bool WriteMemory( uint64_t address, const void* buffer, size_t size ) override;
	bool WriteToReadOnlyMemory( uint64_t address, const void* buffer, size_t size ) override;

private:
	struct CopyMemoryBufferInfo
	{
		uint64_t caseNumber;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	};

	struct GetPhysAddressBufferInfo
	{
		uint64_t caseNumber;
		uint64_t reserved;
		uint64_t returnPhysicalAddress;
		uint64_t addressToTranslate;
	};

	struct MapIoSpaceBufferInfo
	{
		uint64_t caseNumber;
		uint64_t reserved;
		uint64_t returnValue;
		uint64_t returnVirtualAddress;
		uint64_t physicalAddressToMap;
		uint32_t size;
	};

	struct UnmapIoSpaceBufferInfo
	{
		uint64_t caseNumber;
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virtAddress;
		uint64_t reserved3;
		uint32_t numberOfBytes;
	};

	bool CallDriver( void* inputBuffer, DWORD inputLength );
	bool MemCopy( uint64_t destination, uint64_t source, uint64_t size );
	bool GetPhysicalAddress( uint64_t address, uint64_t* outPhysicalAddress );
	uint64_t MapIoSpace( uint64_t physicalAddress, uint32_t size );
	bool UnmapIoSpace( uint64_t address, uint32_t size );
};
