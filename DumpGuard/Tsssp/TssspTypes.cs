using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace DumpGuard.Tsssp
{
    internal class TssspTypes
    {
        [Flags]
        public enum TSRequestFlags : byte
        {
            None = 0,
            ClientNonce = 0x08,
            ErrorCode = 0x10,
            PubKeyAuth = 0x20,
            AuthInfo = 0x40,
            NegoTokens = 0x80
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TSRequest : IDisposable
        {
            public TSRequestFlags Flags;
            public int Version;
            public LinkedList<OCTET_STRING> NegoTokens;
            public OCTET_STRING AuthInfo;
            public OCTET_STRING PubKeyAuth;
            public int ErrorCode;
            public OCTET_STRING ClientNonce;

            public TSRequest(int version)
            {
                Flags = TSRequestFlags.None;
                Version = version;
                NegoTokens = default;
                AuthInfo = default;
                PubKeyAuth = default;
                ErrorCode = default;
                ClientNonce = default;
            }

            public void SetNegoTokens(IEnumerable<OCTET_STRING> tokens)
            {
                Flags |= TSRequestFlags.NegoTokens;
                NegoTokens = new LinkedList<OCTET_STRING>(tokens);
            }

            public void SetPubKeyAuth(byte[] pubkey_auth)
            {
                Flags |= TSRequestFlags.PubKeyAuth;
                PubKeyAuth = new OCTET_STRING(pubkey_auth);
            }

            public void Dispose()
            {
                NegoTokens.Dispose();
                AuthInfo.Dispose();
                PubKeyAuth.Dispose();
                ClientNonce.Dispose();
            }
        }

        public enum TSCREDENTIAL_TYPE : int
        {
            Password = 1,
            SmartCard = 2,
            Loopback = 4,
            RemoteGuard = 6,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TSCredentials
        {
            public TSCREDENTIAL_TYPE CredType;
            public OCTET_STRING Credentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TSRemoteGuardPackageCred
        {
            public OCTET_STRING PackageName;
            public OCTET_STRING CredBuffer;
        }

        [Flags]
        public enum TSRemoteGuardCredsFlags : byte
        {
            SupplementalCreds = 0x80
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TSRemoteGuardCreds
        {
            public TSRemoteGuardCredsFlags Flags;
            public TSRemoteGuardPackageCred LogonCred;
            public LinkedList<TSRemoteGuardPackageCred> SupplementalCreds;
        }

        public enum TSRemoteGuardVersion : uint
        {
            V1 = 0,
        }

        [Flags]
        public enum TSRemoteGuardInnerPacketFlags : byte
        {
            None = 0,
            Version = 0x80,
            Extension = 0x40,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TSRemoteGuardInnerPacket : IDisposable
        {
            public TSRemoteGuardInnerPacketFlags Flags;
            public TSRemoteGuardVersion Version;
            public OCTET_STRING PackageName;
            public OCTET_STRING Buffer;
            public OPEN_TYPE Extension;

            public TSRemoteGuardInnerPacket(string package_name, byte[] buffer)
            {
                Flags = TSRemoteGuardInnerPacketFlags.None;
                Version = TSRemoteGuardVersion.V1;
                PackageName = new OCTET_STRING(Encoding.Unicode.GetBytes(package_name));
                Buffer = new OCTET_STRING(buffer);
                Extension = default;
            }

            public void Dispose()
            {
                PackageName.Dispose();
                Buffer.Dispose();
                Extension.Dispose();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RDPEAR_PAYLOAD_HEADER
        {
            public int ProtocolMagic;      // A 32-bit integer that MUST be equal to the value 0x4eacc3c8.
            public int Length;             // A 32-bit unsigned integer value that contains the overall length of the message.
            public int Version;            // A 32-bit unsigned integer value describing the RDPEAR Protocol version. This MUST be 0x00000000.
            public int Reserved;           // Reserved for future use.
            public IntPtr TsPkgContext;    // Used by the RDPEAR virtual channel ([MSDN-TSVC]) to maintain internal consistency across messages. This field MUST be zero in all network messages.
            // char Payload[0];     // The encrypted portion of the RDPEAR Outer Layer. The plaintext data consists of an Abstract Syntax Notation One (ASN.1) structure, as specified in [X680], and is encoded using Distinguished Encoding Rules (DER), as specified in [X690] section 10. The plaintext data is encrypted using the negotiated security context between the client and server as part of [MS-CSSP].

            public RDPEAR_PAYLOAD_HEADER(int size, IntPtr context)
            {
                ProtocolMagic = 0x4eacc3c8;
                Length = size;
                Version = 0;
                Reserved = 0;
                TsPkgContext = context;
            }

            public bool IsCorrectMagic()
            {
                return (ProtocolMagic == 0x4eacc3c8);
            }
        }
    }
}
