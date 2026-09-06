#pragma once
#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_KKYUM)

#include "../Common/KernelRwCallBackend.h"

class KKYUMBackend final : public KernelRwCallBackend
{
public:
	KKYUMBackend( )
	{
		m_CallGate = KernelCallGate::TableSwap;
	}

	std::string Name( ) const override;

protected:
	NTSTATUS LoadDevice( ) override;
	NTSTATUS UnloadDevice( ) override;
	bool ReadMemory( uint64_t address, void* buffer, size_t size ) override;
	bool WriteMemory( uint64_t address, const void* buffer, size_t size ) override;

private:
	#pragma pack(push, 1)
	struct CopyEntry
	{
		uint64_t RemoteAddress;
		uint64_t LocalAddress;
		uint64_t Size;
	};

	struct CopyRequest
	{
		uint32_t TargetPID;
		uint32_t EntryCount;
		CopyEntry Entries[ 1 ];
	};
	#pragma pack(pop)

	bool CopyKernelMemory( DWORD ioctl, uint64_t address, void* buffer, size_t size );
};




#endif // KZEROMAPPER_ENABLE_KKYUM
