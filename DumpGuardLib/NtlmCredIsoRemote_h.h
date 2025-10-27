

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 04:14:07 2038
 */
/* Compiler settings for NtlmCredIsoRemote.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */

#include "midles.h"

#ifndef __NtlmCredIsoRemote_h_h__
#define __NtlmCredIsoRemote_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "BaseTypes.h"
#include "RemoteGuardCallIds.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_NtlmCredIsoRemote_0000_0000 */
/* [local] */ 

typedef /* [public][public][public][public][public][public][public][public][public][public][public] */ 
enum __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0001
    {
        RemoteInvalidCredKey	= 0,
        RemoteIUMCredKey	= ( RemoteInvalidCredKey + 1 ) ,
        RemoteDomainUserCredKey	= ( RemoteIUMCredKey + 1 ) ,
        RemoteLocalUserCredKey	= ( RemoteDomainUserCredKey + 1 ) ,
        RemoteExternallySuppliedCredKey	= ( RemoteLocalUserCredKey + 1 ) 
    } 	MSV1_0_REMOTE_CREDENTIAL_KEY_TYPE;

typedef /* [public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0002
    {
    byte Data[ 8 ];
    } 	NT_CHALLENGE;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0003
    {
    byte Data[ 24 ];
    } 	NT_RESPONSE;

typedef /* [public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0004
    {
    byte Response[ 16 ];
    byte ChallengeFromClient[ 8 ];
    } 	MSV1_0_LM3_RESPONSE;

typedef /* [public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0005
    {
    byte Data[ 8 ];
    } 	LM_SESSION_KEY;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0006
    {
    byte Data[ 16 ];
    } 	USER_SESSION_KEY;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0007
    {
    byte Data[ 16 ];
    } 	MSV1_0_NT_OWF_PASSWORD;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0008
    {
    byte Data[ 16 ];
    } 	MSV1_0_LM_OWF_PASSWORD;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0009
    {
    byte Data[ 20 ];
    } 	MSV1_0_SHA_OWF_PASSWORD;

typedef /* [public][public][public][public][public][public][public][public][public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0010
    {
    byte Data[ 20 ];
    } 	MSV1_0_REMOTE_CREDENTIAL_KEY;

typedef /* [public][public][public][public][public][public][public][public][public][public][public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0011
    {
    unsigned char NtPasswordPresent;
    unsigned char LmPasswordPresent;
    unsigned char ShaPasswordPresent;
    MSV1_0_REMOTE_CREDENTIAL_KEY_TYPE CredentialKeyType;
    MSV1_0_REMOTE_CREDENTIAL_KEY CredentialKeySecret;
    unsigned int EncryptedSize;
    /* [size_is] */ unsigned char *EncryptedSecrets;
    } 	MSV1_0_REMOTE_ENCRYPTED_SECRETS;

typedef struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0011 *PMSV1_0_REMOTE_ENCRYPTED_SECRETS;

typedef /* [public][public][public] */ struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0012
    {
    unsigned char NtPasswordPresent;
    unsigned char LmPasswordPresent;
    unsigned char ShaPasswordPresent;
    MSV1_0_REMOTE_CREDENTIAL_KEY_TYPE CredentialKeyType;
    MSV1_0_REMOTE_CREDENTIAL_KEY CredentialKeySecret;
    MSV1_0_NT_OWF_PASSWORD NtOwfPassword;
    MSV1_0_LM_OWF_PASSWORD LmOwfPassword;
    MSV1_0_SHA_OWF_PASSWORD ShaOwfPassword;
    } 	MSV1_0_REMOTE_PLAINTEXT_SECRETS;

typedef struct __MIDL___MIDL_itf_NtlmCredIsoRemote_0000_0000_0012 *PMSV1_0_REMOTE_PLAINTEXT_SECRETS;



extern RPC_IF_HANDLE __MIDL_itf_NtlmCredIsoRemote_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_NtlmCredIsoRemote_0000_0000_v0_0_s_ifspec;

#ifndef __NtlmCredIsoRemote_INTERFACE_DEFINED__
#define __NtlmCredIsoRemote_INTERFACE_DEFINED__

/* interface NtlmCredIsoRemote */
/* [explicit_handle][version][uuid] */ 

typedef struct _NtlmCredIsoRemoteInput
    {
    RemoteGuardCallId CallId;
    /* [switch_is][switch_type] */ union 
        {
        /* [case()] */ struct 
            {
            unsigned int MaxSupportedVersion;
            } 	NegotiateVersion;
        /* [case()] */ struct 
            {
            MSV1_0_REMOTE_PLAINTEXT_SECRETS *Credential;
            } 	;
        /* [case()] */ struct 
            {
            MSV1_0_REMOTE_ENCRYPTED_SECRETS *Credential;
            IUM_UNICODE_STRING *UserName;
            IUM_UNICODE_STRING *LogonDomainName;
            IUM_UNICODE_STRING *ServerName;
            byte ChallengeToClient[ 8 ];
            } 	Lm20GetNtlm3ChallengeResponse;
        /* [case()] */ struct 
            {
            NT_CHALLENGE *NtChallenge;
            MSV1_0_REMOTE_ENCRYPTED_SECRETS *Credential;
            } 	CalculateNtResponse;
        /* [case()] */ struct 
            {
            NT_RESPONSE *NtResponse;
            MSV1_0_REMOTE_ENCRYPTED_SECRETS *Credential;
            } 	CalculateUserSessionKeyNt;
        /* [case()] */ struct 
            {
            MSV1_0_REMOTE_ENCRYPTED_SECRETS *LhsCredential;
            MSV1_0_REMOTE_ENCRYPTED_SECRETS *RhsCredential;
            } 	CompareCredentials;
        } 	;
    } 	NtlmCredIsoRemoteInput;

typedef /* [allocate][decode][encode] */ struct _NtlmCredIsoRemoteInput *PNtlmCredIsoRemoteInput;

typedef struct _NtlmCredIsoRemoteOutput
    {
    RemoteGuardCallId CallId;
    int Status;
    /* [switch_is][switch_type] */ union 
        {
        /* [case()] */ struct 
            {
            unsigned int VersionToUse;
            } 	NegotiateVersion;
        /* [case()] */ struct 
            {
            MSV1_0_REMOTE_ENCRYPTED_SECRETS Credential;
            } 	ProtectCredential;
        /* [case()] */ struct 
            {
            unsigned short Ntlm3ResponseLength;
            /* [size_is] */ unsigned char *Ntlm3Response;
            MSV1_0_LM3_RESPONSE Lm3Response;
            USER_SESSION_KEY UserSessionKey;
            LM_SESSION_KEY LmSessionKey;
            } 	Lm20GetNtlm3ChallengeResponse;
        /* [case()] */ struct 
            {
            NT_RESPONSE NtResponse;
            } 	CalculateNtResponse;
        /* [case()] */ struct 
            {
            USER_SESSION_KEY UserSessionKey;
            } 	CalculateUserSessionKeyNt;
        /* [case()] */ struct 
            {
            IUM_BOOL AreNtOwfsEqual;
            IUM_BOOL AreLmOwfsEqual;
            IUM_BOOL AreShaOwfsEqual;
            } 	CompareCredentials;
        } 	;
    } 	NtlmCredIsoRemoteOutput;

typedef /* [allocate][decode][encode] */ struct _NtlmCredIsoRemoteOutput *PNtlmCredIsoRemoteOutput;



extern RPC_IF_HANDLE NtlmCredIsoRemote_v1_0_c_ifspec;
extern RPC_IF_HANDLE NtlmCredIsoRemote_v1_0_s_ifspec;
#endif /* __NtlmCredIsoRemote_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */


size_t
PNtlmCredIsoRemoteInput_AlignSize(
    handle_t _MidlEsHandle,
    PNtlmCredIsoRemoteInput * _pType);

size_t
PNtlmCredIsoRemoteOutput_AlignSize(
    handle_t _MidlEsHandle,
    PNtlmCredIsoRemoteOutput * _pType);


void
PNtlmCredIsoRemoteInput_Encode(
    handle_t _MidlEsHandle,
    PNtlmCredIsoRemoteInput * _pType);

void
PNtlmCredIsoRemoteOutput_Encode(
    handle_t _MidlEsHandle,
    PNtlmCredIsoRemoteOutput * _pType);


void
PNtlmCredIsoRemoteInput_Decode(
    handle_t _MidlEsHandle,
    PNtlmCredIsoRemoteInput * _pType);

void
PNtlmCredIsoRemoteOutput_Decode(
    handle_t _MidlEsHandle,
    PNtlmCredIsoRemoteOutput * _pType);


void
PNtlmCredIsoRemoteInput_Free(
    handle_t _MidlEsHandle,
    PNtlmCredIsoRemoteInput * _pType);

void
PNtlmCredIsoRemoteOutput_Free(
    handle_t _MidlEsHandle,
    PNtlmCredIsoRemoteOutput * _pType);

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


