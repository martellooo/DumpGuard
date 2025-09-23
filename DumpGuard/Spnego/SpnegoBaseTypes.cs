using System;
using System.Runtime.InteropServices;

namespace DumpGuard.Spnego
{
    internal class SpnegoBaseTypes
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MechTypeList : IDisposable
        {
            public LinkedList<OBJECT_IDENTIFIER> MechTypes;

            public MechTypeList(LinkedList<OBJECT_IDENTIFIER> types)
            {
                MechTypes = types;
            }

            public void Dispose()
            {
                MechTypes.Dispose();
            }
        }

        [Flags]
        public enum NegHintsFlags : ushort
        {
            HintAddress = 0x40,
            HintName = 0x80
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NegHints
        {
            public NegHintsFlags Flags;
            [MarshalAs(UnmanagedType.LPStr)] public string HintName;
            public OCTET_STRING HintAddress;
        }

        [Flags]
        public enum NegTokenInitFlags : ushort
        {
            MechListMic = 0x20,
            MechToken = 0x40,
            ReqFlags = 0x80,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NegTokenInit
        {
            public NegTokenInitFlags Flags;
            public LinkedList<OBJECT_IDENTIFIER> MechTypes;
            public BIT_STRING ReqFlags;
            public OCTET_STRING MechToken;
            public OCTET_STRING MechListMic;
        }

        [Flags]
        public enum NegTokenInit2Flags : ushort
        {
            NegHints = 0x08,
            MechListMic = 0x10,
            MechToken = 0x20,
            ReqFlags = 0x40,
            MechTypes = 0x80
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NegTokenInit2
        {
            public NegTokenInit2Flags Flags;
            public LinkedList<OBJECT_IDENTIFIER> MechTypes;
            public BIT_STRING ReqFlags;
            public OCTET_STRING MechToken;
            public OCTET_STRING MechListMic;
            public NegHints NegHints;
        }

        [Flags]
        public enum NegResult : uint
        {
            AcceptCompleted = 0,
            AcceptIncomplete,
            Reject,
            RequestMic,
        }

        [Flags]
        public enum NegTokenTargFlags : ushort
        {
            None = 0,
            MechListMic = 0x10,
            ResponseToken = 0x20,
            SupportedMech = 0x40,
            NegResult = 0x80
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NegTokenTarg : IDisposable
        {
            public NegTokenTargFlags Flags;
            public NegResult NegResult;
            public OBJECT_IDENTIFIER SupportedMech;
            public OCTET_STRING ResponseToken;
            public OCTET_STRING MechListMic;

            public NegTokenTarg(NegResult? result, string supported_mech, byte[] response_token, byte[] mech_mic_list)
            {
                Flags = NegTokenTargFlags.None;

                if (!result.HasValue)
                    NegResult = default;
                else
                {
                    Flags |= NegTokenTargFlags.NegResult;
                    NegResult = result.Value;
                }

                if (string.IsNullOrEmpty(supported_mech))
                    SupportedMech = default;
                else
                {
                    Flags |= NegTokenTargFlags.SupportedMech;
                    SupportedMech = new OBJECT_IDENTIFIER(supported_mech);
                }

                if (response_token == null)
                    ResponseToken = default;
                else
                {
                    Flags |= NegTokenTargFlags.ResponseToken;
                    ResponseToken = new OCTET_STRING(response_token);
                }

                if (mech_mic_list == null)
                    MechListMic = default;
                else
                {
                    Flags |= NegTokenTargFlags.MechListMic;
                    MechListMic = new OCTET_STRING(mech_mic_list);
                }
            }

            public void Dispose()
            {
                SupportedMech.Dispose();
                ResponseToken.Dispose();
                MechListMic.Dispose();
            }
        }

        [Flags]
        public enum NegotiationTokenChoice : ushort
        {
            NegTokenInit = 1,
            NegTokenTarg = 2,
            NegTokenInit2 = 3
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NegotiationToken : IDisposable
        {
            public NegotiationTokenChoice Choice;
            public NegTokenTarg NegTokenTarg;

            public NegotiationToken(NegResult? result, string supported_mech, byte[] response_token, byte[] mech_mic_list)
            {
                Choice = NegotiationTokenChoice.NegTokenTarg;
                NegTokenTarg = new NegTokenTarg(result, supported_mech, response_token, mech_mic_list);
            }

            public void Dispose()
            {
                NegTokenTarg.Dispose();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct InitialNegToken
        {
            public OBJECT_IDENTIFIER SpnegoMech;
            public NegotiationTokenChoice Choice;
            public NegTokenInit NegTokenInit;
        }
    }
}
