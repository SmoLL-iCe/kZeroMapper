#pragma once
#include "MapperBackend.h"

NTSTATUS InitializeMapperRuntime( );
NTSTATUS RunMapperBackend( IMapperBackend& backend, void* pDrvData, size_t szDataSize, bool bClean );
