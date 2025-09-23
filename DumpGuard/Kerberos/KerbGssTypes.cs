using System;
using System.Runtime.InteropServices;

namespace DumpGuard.Kerberos
{
    internal class KerbGssTypes
    {
        public enum KERB_GSS_TOKEN_ID : ushort
        {
            None = 0,

            KerbApReq               = 0x0001,
            KerbApRep               = 0x0002,
            KerbError               = 0x0003,
            KerbTgtReq              = 0x0004,
            KerbTgtRep              = 0x0005,

            KerbGssMic              = 0x0101,
            KerbGssWrap             = 0x0102,
            KerbExportedNameToken   = 0x0104,

            KerbGssMicToken         = 0x0404,
            KerbGssWrapToken        = 0x0405,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct InitialContextToken : IDisposable
        {
            public OBJECT_IDENTIFIER MechType;
            public KERB_GSS_TOKEN_ID TokenId;
            public OPEN_TYPE InnerToken;

            public InitialContextToken(string mech_type, KERB_GSS_TOKEN_ID token_id, byte[] inner_token)
            {
                MechType = new OBJECT_IDENTIFIER(mech_type);
                TokenId = token_id;
                InnerToken = new OPEN_TYPE(inner_token);
            }

            public void Dispose()
            {
                InnerToken.Dispose();
            }
        }

        [Flags]
        public enum GSS_TOKEN_FLAGS : byte
        {
            None = 0,
            SentByAcceptor  = 0b00000001,
            Sealed          = 0b00000010,
            AcceptorSubKey  = 0b00000100,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIC_TOKEN_HEADER
        {
            public KERB_GSS_TOKEN_ID TokenId;
            public GSS_TOKEN_FLAGS Flags;
            public byte Filler1;
            public uint Filler2;
            public ulong SequenceNumber;
            
            public MIC_TOKEN_HEADER(GSS_TOKEN_FLAGS flags, ulong sequence_number)
            {
                TokenId = KERB_GSS_TOKEN_ID.KerbGssMicToken;
                Flags = flags;
                Filler1 = 0xff;
                Filler2 = 0xffffffff;
                SequenceNumber = Interop.SwapEndianness(sequence_number);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct KERB_GSS_SIGNATURE_HEADER
        {
            public KERB_GSS_TOKEN_ID TokenId;
            public GSS_TOKEN_FLAGS Flags;
            public byte Filler;
            public ushort ExtraCount;
            public ushort RightRotationCount;
            public ulong SequenceNumber;

            public KERB_GSS_SIGNATURE_HEADER(GSS_TOKEN_FLAGS flags, ushort extra_count, ushort right_rotation_count, ulong sequence_number)
            {
                TokenId = KERB_GSS_TOKEN_ID.KerbGssWrapToken;
                Flags = flags;
                Filler = 0xff;
                ExtraCount = Interop.SwapEndianness(extra_count);
                RightRotationCount = Interop.SwapEndianness(right_rotation_count);
                SequenceNumber = Interop.SwapEndianness(sequence_number);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct KERB_GSS_SEAL_SIGNATURE
        {
            public KERB_GSS_SIGNATURE_HEADER Header;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] EncryptedHeader;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)] public byte[] Checksum;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Confounder;

            public KERB_GSS_SEAL_SIGNATURE(GSS_TOKEN_FLAGS flags, ushort extra_count, ushort right_rotation_count, ulong sequence_number)
            {
                Header = new KERB_GSS_SIGNATURE_HEADER(flags, extra_count, right_rotation_count, sequence_number);
                EncryptedHeader = null;
                Checksum = null;
                Confounder = null;
            }
        }
    }
}
