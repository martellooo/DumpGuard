using System;
using System.Runtime.InteropServices;

namespace DumpGuard.Ntlm
{
    internal class NtlmTypes
    {
        public enum MSV1_0_CREDENTIAL_KEY_TYPE : uint
        {
            InvalidCredKey,
            DeprecatedIUMCredKey,
            DomainUserCredKey,
            LocalUserCredKey,
            ExternallySuppliedCredKey
        }

        public enum MSV1_0_CRED_VERSION : uint
        {
            V1 = 0,
            V2 = 2,
            V3 = 4,
            IUM = 0xffff0001,
            REMOTE = 0xffff0002,
            ARSO = 0xffff0003,
            INVALID = 0xffffffff
        }

        [Flags]
        public enum MSV1_0_CRED_FLAGS : uint
        {
            LmPresent       = 0x0001,
            NtPresent       = 0x0002,
            CredKeyPresent  = 0x0008,
            ShaPresent      = 0x0010,
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL_HEADER
        {
            public MSV1_0_CRED_VERSION Version;
            public MSV1_0_CRED_FLAGS Flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)] public byte[] CredentialKey;
            public MSV1_0_CREDENTIAL_KEY_TYPE CredentialKeyType;
            public int EncryptedCredsSize;
            // [MarshalAs(UnmanagedType.ByValArray, SizeConst = variable)] public byte[] EncryptedCreds;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_REMOTE_ENCRYPTED_SECRETS
        {
            public byte NtPasswordPresent;
            public byte LmPasswordPresent;
            public byte ShaPasswordPresent;
            public MSV1_0_CREDENTIAL_KEY_TYPE CredentialKeyType;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)] public byte[] CredentialKeySecret;
            public int EncryptedSize;
            public IntPtr EncryptedSecrets;

            public MSV1_0_REMOTE_ENCRYPTED_SECRETS(MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL_HEADER ntlm_cred_header, IntPtr buffer)
            {
                NtPasswordPresent = (byte)(ntlm_cred_header.Flags.HasFlag(MSV1_0_CRED_FLAGS.NtPresent) ? 1 : 0);
                LmPasswordPresent = (byte)(ntlm_cred_header.Flags.HasFlag(MSV1_0_CRED_FLAGS.LmPresent) ? 1 : 0);
                ShaPasswordPresent = (byte)(ntlm_cred_header.Flags.HasFlag(MSV1_0_CRED_FLAGS.ShaPresent) ? 1 : 0);

                if (ntlm_cred_header.Flags.HasFlag(MSV1_0_CRED_FLAGS.CredKeyPresent))
                {
                    CredentialKeyType = ntlm_cred_header.CredentialKeyType;
                    CredentialKeySecret = ntlm_cred_header.CredentialKey;
                }
                else
                {
                    CredentialKeyType = default;
                    CredentialKeySecret = default;
                }

                EncryptedSize = ntlm_cred_header.EncryptedCredsSize;
                EncryptedSecrets = buffer;
            }
        }

        public enum RemoteGuardCallId : uint
        {
            RemoteCallNtlmMinimum = 0x200,
            RemoteCallNtlmNegotiateVersion = 0x200,
            RemoteCallNtlmProtectCredential = (RemoteCallNtlmNegotiateVersion + 1),
            RemoteCallNtlmLm20GetNtlm3ChallengeResponse = (RemoteCallNtlmProtectCredential + 1),
            RemoteCallNtlmCalculateNtResponse = (RemoteCallNtlmLm20GetNtlm3ChallengeResponse + 1),
            RemoteCallNtlmCalculateUserSessionKeyNt = (RemoteCallNtlmCalculateNtResponse + 1),
            RemoteCallNtlmCompareCredentials = (RemoteCallNtlmCalculateUserSessionKeyNt + 1),
            RemoteCallNtlmMaximum = 0x2ff,
            RemoteCallInvalid = 0xffff
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NT_CHALLENGE
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NT_RESPONSE
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)] public byte[] Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NtlmCredIsoRemoteInput_CalculateNtResponse
        {
            public RemoteGuardCallId CallId;
            public IntPtr NtChallenge;
            public IntPtr Credential;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NtlmCredIsoRemoteOutput_CalculateNtResponse
        {
            public RemoteGuardCallId CallId;
            public int Status;
            public NT_RESPONSE NtResponse;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct NtlmCredIsoRemoteHeader
        {
            public ushort AlwaysOne;   // Must be 1
            public ushort Sequence;    // Mirrored in output
            public uint Reserved1;
            public uint Reserved2;
            public uint Reserved3;

            public NtlmCredIsoRemoteHeader(ushort sequence)
            {
                AlwaysOne = 1;
                Sequence = sequence;
                Reserved1 = default;
                Reserved2 = default;
                Reserved3 = default;
            }
        }
    }
}
