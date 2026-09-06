#pragma once 
#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)
#include <vector>
#include <winnt.h>

class DriverParse
{
public:
	DriverParse( void* pDrvData, size_t szDataSize );

	~DriverParse( );

	std::vector<uint8_t> GetMappedDrv( void* CustomGetProcAddress );

	size_t GetImgSize( ) const;
private:
	std::vector<uint8_t>	m_Image {};

	std::vector<uint8_t>	m_ImageMapped {};

	PIMAGE_DOS_HEADER		  m_pImgDosHeader		= nullptr;

	PIMAGE_NT_HEADERS64		m_pImgNtHeaders		= nullptr;

	PIMAGE_SECTION_HEADER	m_pSectionHeader	= nullptr;

	template<typename T>
	__forceinline T* GetRva( const unsigned long Offset )
	{
		return ( T* )::ImageRvaToVa( m_pImgNtHeaders, m_Image.data( ), Offset, nullptr );
	}
};
