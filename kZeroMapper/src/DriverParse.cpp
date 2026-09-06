#include <Windows.h>
#include "DriverParse.h"
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")
#include "Common/MapperBackend.h"

DriverParse::DriverParse( void* pDrvData, size_t szDataSize )
{
	m_Image.clear( );

	m_Image.reserve( szDataSize );

	m_Image.resize( szDataSize );

	memcpy( m_Image.data( ), pDrvData, szDataSize );
	
	m_pImgDosHeader		= reinterpret_cast<PIMAGE_DOS_HEADER>( m_Image.data( ) );

	m_pImgNtHeaders		= reinterpret_cast<PIMAGE_NT_HEADERS64>( reinterpret_cast<uintptr_t>( m_pImgDosHeader ) + m_pImgDosHeader->e_lfanew );

	m_pSectionHeader	= reinterpret_cast<IMAGE_SECTION_HEADER*>( reinterpret_cast<uintptr_t>( &m_pImgNtHeaders->OptionalHeader
		) + m_pImgNtHeaders->FileHeader.SizeOfOptionalHeader );
}

size_t DriverParse::GetImgSize( ) const
{
	return m_pImgNtHeaders->OptionalHeader.SizeOfImage;
};

std::vector<uint8_t> DriverParse::GetMappedDrv( void* CustomGetProcAddress )
{
	ULONG Size = 0;

	auto pImportDesc = static_cast<PIMAGE_IMPORT_DESCRIPTOR>( ImageDirectoryEntryToData(
		m_Image.data( ), FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Size ) );

	if ( !pImportDesc )
	{
		LOGS( "[-] - [VBOX] No imports!" );
		return {};
	}

	for ( ; pImportDesc->Name; pImportDesc++ )
	{
		// const auto moduleName  = GetRva<char>( pImportDesc->Name );

		auto pImgThunkData   = ( pImportDesc->OriginalFirstThunk )
			? GetRva<IMAGE_THUNK_DATA>( pImportDesc->OriginalFirstThunk )
			: GetRva<IMAGE_THUNK_DATA>( pImportDesc->FirstThunk );

		auto pImgFuncData    = GetRva<IMAGE_THUNK_DATA64>( pImportDesc->FirstThunk );

		for ( ; pImgThunkData->u1.AddressOfData; pImgThunkData++, pImgFuncData++ )
		{
			uintptr_t FunctionAddress = 0;

			const auto Ordinal = ( pImgThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64 ) != 0;

			if ( Ordinal )
			{
				const auto ImportOrdinal = reinterpret_cast<LPCSTR>( pImgThunkData->u1.Ordinal & 0xffff );

				FunctionAddress = reinterpret_cast<uint16_t( __fastcall* )( LPCSTR )>( CustomGetProcAddress )( ImportOrdinal );

				//printf("function: %hu [0x%llX]\n", reinterpret_cast<uint16_t>(ImportOrdinal), FunctionAddress);
			}
			else
			{
				const auto pImgImportByName     = GetRva<IMAGE_IMPORT_BY_NAME>( *reinterpret_cast<DWORD*>( pImgThunkData ) );

				const auto NameOfImport           = static_cast<char*>( pImgImportByName->Name );

				FunctionAddress                    = reinterpret_cast<uintptr_t( __fastcall* )( LPCSTR )>( CustomGetProcAddress )( NameOfImport );

				//printf("function: %s [0x%llX]\n", NameOfImport, FunctionAddress);
			}

			//assert(FunctionAddress != 0);
			pImgFuncData->u1.Function = FunctionAddress;
		}
	}

	m_ImageMapped.clear( );

	m_ImageMapped.resize( m_pImgNtHeaders->OptionalHeader.SizeOfImage );

	std::copy_n( m_Image.begin( ), m_pImgNtHeaders->OptionalHeader.SizeOfHeaders, m_ImageMapped.begin( ) );

	m_Image.clear( );

	for ( size_t i = 0; i < m_pImgNtHeaders->FileHeader.NumberOfSections; ++i )
	{
		const auto& pSection     = m_pSectionHeader[ i ];

		//const auto pTarget       = reinterpret_cast<uintptr_t>( m_ImageMapped.data( ) ) + pSection.VirtualAddress;

		//const auto pSource       = reinterpret_cast<uintptr_t>( m_pImgDosHeader ) + pSection.PointerToRawData;

		std::copy_n( m_Image.begin( ) + pSection.PointerToRawData, pSection.SizeOfRawData, m_ImageMapped.begin( ) + pSection.VirtualAddress );

		//printf("copying [%s] 0x%p -> 0x%p [0x%08X]\n", &pSection.Name[0], reinterpret_cast<void*>(pSource), reinterpret_cast<void*>(pTarget), pSection.SizeOfRawData);
	}

	return m_ImageMapped;
}

DriverParse::~DriverParse( )
= default;
