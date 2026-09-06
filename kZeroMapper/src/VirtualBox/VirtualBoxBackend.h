#pragma once
#include "../Common/MapperBackend.h"

class VirtualBoxBackend final : public IMapperBackend
{
public:
	std::string Name( ) const override;
	NTSTATUS Load( ) override;
	NTSTATUS Unload( ) override;
	NTSTATUS Execute( uint8_t* shellCode, uint32_t codeSize ) override;
	bool Clean( ) override { return true; }

	NTSTATUS Status2( ) const;

private:
	HANDLE StartVulnerableDriver( NTSTATUS* outStatus, NTSTATUS* outStatus2 );
	NTSTATUS StopVulnerableDriver( );

	HANDLE m_Device = INVALID_HANDLE_VALUE;
	NTSTATUS m_Status2 = 0;
};
