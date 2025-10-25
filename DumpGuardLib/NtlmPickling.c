#include "NtlmCredIsoRemote_h.h"

BOOL NtlmEncodeCredIsoRemoteInput(PNtlmCredIsoRemoteInput pInput, PVOID* ppvEncoded, ULONG* pcbEncoded)
{
	BOOL Result = FALSE;

	handle_t pHandle = NULL;

	PCHAR pvEncoded = NULL;
	ULONG cbEncoded = 0;

	if (I_RpcMapWin32Status(MesEncodeDynBufferHandleCreate(&pvEncoded, &cbEncoded, &pHandle)) >= 0)
	{
		cbEncoded = (ULONG)PNtlmCredIsoRemoteInput_AlignSize(pHandle, &pInput);

		if (pvEncoded != NULL)
		{
			LocalFree(pvEncoded);
			pvEncoded = NULL;
		}

		ULONG cbBuffer = cbEncoded;
		PBYTE pvBuffer = malloc(cbBuffer);

		if (pvBuffer != NULL)
		{
			pvEncoded = pvBuffer;

			if (I_RpcMapWin32Status(MesBufferHandleReset(pHandle, MES_FIXED_BUFFER_HANDLE, MES_ENCODE, &pvBuffer, cbBuffer, &cbBuffer)) >= 0)
			{
				PNtlmCredIsoRemoteInput_Encode(pHandle, &pInput);

				*ppvEncoded = pvBuffer;
				*pcbEncoded = cbBuffer;

				pvBuffer = NULL;
				Result = TRUE;
			}

			if (pvBuffer != NULL)
				free(pvBuffer);
		}
	}

	if (pHandle != (handle_t)INVALID_HANDLE_VALUE)
		MesHandleFree(pHandle);

	return Result;
}

BOOL NtlmDecodeCredIsoRemoteOutput(PVOID pvOutput, ULONG cbOutput, PNtlmCredIsoRemoteOutput* ppDecoded)
{
	BOOL Result = FALSE;

	handle_t pHandle = NULL;

	if (I_RpcMapWin32Status(MesDecodeBufferHandleCreate(pvOutput, cbOutput, &pHandle)) >= 0)
	{
		PNtlmCredIsoRemoteOutput pDecoded = NULL;
		PNtlmCredIsoRemoteOutput_Decode(pHandle, &pDecoded);

		if (pDecoded != NULL)
		{
			*ppDecoded = pDecoded;

			pDecoded = NULL;
			Result = TRUE;
		}

		if (pDecoded != NULL)
			LocalFree(pDecoded);
	}

	if (pHandle != (handle_t)INVALID_HANDLE_VALUE)
		MesHandleFree(pHandle);

	return Result;
}