#include "msasn1.h"
#include "gssapi.h"
#include "krb5asn1.h"
#include "spnegoasn1.h"
#include "tssspasn1.h"

_Must_inspect_result_ _Ret_maybenull_ _Post_writable_byte_size_(size) 
void* __RPC_USER MIDL_user_allocate(_In_ size_t size)
{
	return LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, size);
}

void __RPC_USER MIDL_user_free(_Pre_maybenull_ _Post_invalid_ void* p)
{
	LocalFree(p);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		if (!ASN1InitializeModule())
			return FALSE;

		if (!TSSSP_Module_Startup())
			return FALSE;

		if (!SPNEGO_Module_Startup())
			return FALSE;

		if (!GSSAPI_Module_Startup())
			return FALSE;

		if (!KRB5_Module_Startup())
			return FALSE;
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		KRB5_Module_Cleanup();
		GSSAPI_Module_Cleanup();
		SPNEGO_Module_Cleanup();
		TSSSP_Module_Cleanup();
	}

	return TRUE;
}