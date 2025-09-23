using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using static DumpGuard.Ntlm.NtlmTypes;

namespace DumpGuard
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LinkedList<T> : IDisposable
        where T : struct
    {
        public IntPtr Head;

        public LinkedList(IEnumerable<T> values)
        {
            Head = BuildLinkedList(values);
        }

        public LinkedList(params T[] values)
            : this((IEnumerable<T>)values)
        {

        }

        public LinkedList(LinkedList<T> other)
            : this(other.ParseList())
        {

        }

        private static IntPtr BuildLinkedList(IEnumerable<T> values)
        {
            var next = IntPtr.Zero;

            foreach (var value in values?.Reverse() ?? Enumerable.Empty<T>())
            {
                var ptr = Marshal.AllocHGlobal(IntPtr.Size + Marshal.SizeOf<T>());

                Marshal.WriteIntPtr(ptr, next);
                Marshal.StructureToPtr(value, ptr + IntPtr.Size, false);

                next = ptr;
            }

            return next;
        }

        public IEnumerable<T> ParseList()
        {
            var current = Head;

            while (current != IntPtr.Zero)
            {
                yield return Marshal.PtrToStructure<T>(current + IntPtr.Size);
                current = Marshal.ReadIntPtr(current);
            }
        }

        public void Dispose()
        {
            var current = Head;

            while (current != IntPtr.Zero)
            {
                var next = Marshal.ReadIntPtr(current);
                var structure = Marshal.PtrToStructure<T>(current + IntPtr.Size);

                if (structure is IDisposable disposable)
                    disposable.Dispose();

                Marshal.DestroyStructure<T>(current + IntPtr.Size);
                Marshal.FreeHGlobal(current);

                current = next;
            }
        }
    }

    internal struct OBJECT_IDENTIFIER : IDisposable
    {
        public LinkedList<int> List;

        public OBJECT_IDENTIFIER(string oid)
        {
            List = new LinkedList<int>(oid.Split('.').Select(s => Convert.ToInt32(s)));
        }

        public override string ToString()
        {
            return string.Join(".", List.ParseList());
        }

        public void Dispose()
        {
            List.Dispose();
        }
    }

    internal struct BIT_STRING : IDisposable
    {
        public int Length;
        public IntPtr Value;

        public BIT_STRING(byte[] bytes)
        {
            Length = bytes.Length * 8;
            Value = Marshal.AllocHGlobal(bytes.Length);

            for (int i = 0; i < bytes.Length; i++)
                Marshal.WriteByte(Value, i, ReverseBits(bytes[i]));
        }

        public BIT_STRING(byte u8) : this(BitConverter.GetBytes(u8)) { }
        public BIT_STRING(ushort u16) : this(BitConverter.GetBytes(u16)) { }
        public BIT_STRING(uint u32) : this(BitConverter.GetBytes(u32)) { }
        public BIT_STRING(ulong u64) : this(BitConverter.GetBytes(u64)) { }

        public void Dispose()
        {
            if (Value != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Value);
                Value = IntPtr.Zero;
            }
        }

        public byte[] ToBytes()
        {
            if ((Length % 8) != 0)
                throw new InvalidOperationException("BIT_STRING has malformed length");

            byte[] bytes = new byte[Length / 8];

            for (int i = 0; i < Length / 8; i++)
                bytes[i] = ReverseBits(Marshal.ReadByte(Value, i));

            return bytes;
        }

        public byte ToByte()        => ToBytes()[0];
        public ushort ToUInt16()    => BitConverter.ToUInt16(ToBytes(), 0);
        public uint ToUInt32()      => BitConverter.ToUInt32(ToBytes(), 0);
        public ulong ToUInt64()     => BitConverter.ToUInt64(ToBytes(), 0);

        public T ToEnum<T>()
            where T : Enum
        {
            var value = default(object);

            switch (Type.GetTypeCode(Enum.GetUnderlyingType(typeof(T))))
            {
                case TypeCode.Byte: value = ToByte(); break;
                case TypeCode.SByte: value = unchecked((sbyte)ToByte()); break;
                case TypeCode.UInt16: value = ToUInt16(); break;
                case TypeCode.Int16: value = unchecked((short)ToUInt16()); break;
                case TypeCode.UInt32: value = ToUInt32(); break;
                case TypeCode.Int32: value = unchecked((int)ToUInt32()); break;
                case TypeCode.UInt64: value = ToUInt64(); break;
                case TypeCode.Int64: value = unchecked((long)ToUInt64()); break;
                default: break;
            }

            return (T)Enum.ToObject(typeof(T), value);
        }

        private static byte ReverseBits(byte b)
        {
            byte r = 0;

            for (int i = 0; i < 8; i++)
                r = (byte)((r << 1) | ((b >> i) & 1));

            return r;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UnmanagedAnsiString
    {
        [MarshalAs(UnmanagedType.LPStr)] public string Value;

        public UnmanagedAnsiString(string value)
        {
            Value = value;
        }

        public UnmanagedAnsiString(UnmanagedAnsiString other)
        {
            Value = other.Value;
        }

        public override string ToString()
        {
            return Value;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UnmanagedUnicodeString
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Value;

        public UnmanagedUnicodeString(string value)
        {
            Value = value;
        }

        public UnmanagedUnicodeString(UnmanagedUnicodeString other)
        {
            Value = other.Value;
        }

        public override string ToString()
        {
            return Value;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr Buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = Length;
            Buffer = Marshal.StringToHGlobalUni(s);
        }

        public UNICODE_STRING(UNICODE_STRING other)
            : this(other.ToString())
        {

        }

        public void Dispose()
        {
            if (Buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(Buffer, Length / 2);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr Buffer;

        public LSA_STRING(string s)
        {
            Length = (ushort)s.Length;
            MaximumLength = Length;
            Buffer = Marshal.StringToHGlobalAnsi(s);
        }

        public LSA_STRING(LSA_STRING other)
            : this(other.ToString())
        {

        }

        public void Dispose()
        {
            if (Buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }
        }

        public byte[] ToBytes()
        {
            if (Buffer == IntPtr.Zero)
                return null;
            else
            {
                byte[] bytes = new byte[Length];
                Marshal.Copy(Buffer, bytes, 0, Length);
                return bytes;
            }
        }

        public override string ToString()
        {
            return Marshal.PtrToStringAnsi(Buffer, Length);
        }
    }

    internal struct CHAR_STRING : IDisposable
    {
        public int Length;
        public IntPtr Value;

        public CHAR_STRING(string str)
        {
            Length = str.Length;
            Value = Marshal.StringToHGlobalAnsi(str);
        }

        public CHAR_STRING(CHAR_STRING other)
            : this(other.ToString())
        {

        }

        public void Dispose()
        {
            if (Value != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Value);
                Value = IntPtr.Zero;
            }
        }

        public override string ToString()
        {
            return Marshal.PtrToStringAnsi(Value, Length);
        }
    }

    internal struct OCTET_STRING : IDisposable
    {
        public int Length;
        public IntPtr Value;

        public OCTET_STRING(byte[] bytes)
        {
            Length = bytes.Length;
            Value = Marshal.AllocHGlobal(Length);
            Marshal.Copy(bytes, 0, Value, Length);
        }

        public OCTET_STRING(OCTET_STRING other)
            : this(other.ToBytes())
        {

        }

        public void Dispose()
        {
            if (Value != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Value);
                Value = IntPtr.Zero;
            }
        }

        public byte[] ToBytes()
        {
            if (Value == IntPtr.Zero)
                return null;
            else
            {
                byte[] bytes = new byte[Length];
                Marshal.Copy(Value, bytes, 0, Length);
                return bytes;
            }
        }
    }

    internal struct OPEN_TYPE : IDisposable
    {
        public int Length;
        public IntPtr Data;
        
        public OPEN_TYPE(byte[] bytes)
        {
            Length = bytes.Length;
            Data = Marshal.AllocHGlobal(Length);
            Marshal.Copy(bytes, 0, Data, Length);
        }

        public OPEN_TYPE(OPEN_TYPE other)
            : this(other.ToBytes())
        {

        }

        public void Dispose()
        {
            if (Data != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Data);
                Data = IntPtr.Zero;
            }
        }

        public byte[] ToBytes()
        {
            byte[] bytes = new byte[Length];
            Marshal.Copy(Data, bytes, 0, Length);
            return bytes;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_INT
    {
        public uint LowPart;
        public int HighPart;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_HANDLE
    {
        public IntPtr LowPart;
        public IntPtr HighPart;

        public void Reset()
        {
            LowPart = IntPtr.Zero;
            HighPart = IntPtr.Zero;
        }
    };

    public enum SecBufferType : int
    {
        SECBUFFER_EMPTY = 0,
        SECBUFFER_DATA = 1,
        SECBUFFER_TOKEN = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer : IDisposable
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;

        public SecBuffer(int size)
        {
            cbBuffer = size;
            BufferType = Convert.ToInt32(SecBufferType.SECBUFFER_TOKEN);

            if (size == 0)
                pvBuffer = IntPtr.Zero;
            else
                pvBuffer = Marshal.AllocHGlobal(size);
        }

        public SecBuffer(byte[] bytes) :
            this(bytes.Length)
        {
            Marshal.Copy(bytes, 0, pvBuffer, cbBuffer);
        }

        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc : IDisposable
    {
        public uint ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;

        public SecBufferDesc(params SecBuffer[] buffers)
        {
            ulVersion = 0; // SECBUFFER_VERSION

            if (buffers == null || buffers.Length == 0)
            {
                cBuffers = 0;
                pBuffers = IntPtr.Zero;
            }
            else
            {
                cBuffers = buffers.Length;
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>() * cBuffers);

                for (int i = 0; i < cBuffers; i++)
                {
                    int offset = Marshal.SizeOf<SecBuffer>() * i;
                    Marshal.StructureToPtr(buffers[i], pBuffers + offset, false);
                }
            }
        }

        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }
    }

    public sealed class SecBufferDescWrapper : IDisposable
    {
        private SecBuffer[] ManagedBuffers { get; set; }

        public SecBufferDescWrapper(params SecBuffer[] buffers)
        {
            ManagedBuffers = buffers;
        }

        public SecBufferDesc GetNativeBuffer()
        {
            return new SecBufferDesc(ManagedBuffers);
        }

        public void SetNativeBuffer(SecBufferDesc buffer)
        {
            var buffers = new SecBuffer[buffer.cBuffers];

            for (int i = 0; i < buffer.cBuffers; i++)
            {
                int offset = Marshal.SizeOf<SecBuffer>() * i;
                buffers[i] = Marshal.PtrToStructure<SecBuffer>(buffer.pBuffers + offset);
            }

            ManagedBuffers = buffers;
        }

        public byte[] GetBuffer(int index)
        {
            var buffer = ManagedBuffers[index];
            var bytes = new byte[buffer.cbBuffer];
            Marshal.Copy(buffer.pvBuffer, bytes, 0, buffer.cbBuffer);
            return bytes;
        }

        public void SetBuffer(int index, byte[] bytes)
        {
            ManagedBuffers[index] = new SecBuffer(bytes);
        }

        public void Dispose()
        {
            foreach (var SecBuffer in ManagedBuffers)
                SecBuffer.Dispose();

            ManagedBuffers = null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    public enum SECURITY_LOGON_TYPE : uint
    {
        UndefinedLogonType = 0,
        Interactive = 2,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock,
        NetworkCleartext,
        NewCredentials,
        RemoteInteractive,
        CachedInteractive,
        CachedRemoteInteractive,
        CachedUnlock
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_LOGON_SESSION_DATA
    {
        public uint Size;
        public LUID LoginID;
        public UNICODE_STRING UserName;
        public UNICODE_STRING LogonDomain;
        public UNICODE_STRING AuthenticationPackage;
        public SECURITY_LOGON_TYPE LogonType;
        public uint Session;
        public IntPtr Sid;
    }

    [Flags]
    public enum MSV1_0_GETCHALLENRESP_ParameterControl : uint
    {
        USE_PRIMARY_PASSWORD = 0x01,
        RETURN_PRIMARY_USERNAME = 0x02,
        RETURN_PRIMARY_LOGON_DOMAINNAME = 0x04,
        GCR_VSM_PROTECTED_PASSWORD = 0x4000 // Password is VSM protected
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSV1_0_GETCHALLENRESP_REQUEST
    {
        public int MessageType;
        public MSV1_0_GETCHALLENRESP_ParameterControl ParameterControl;
        public LUID LogonId;
        public UNICODE_STRING Password;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] ChallengeToClient;
        public UNICODE_STRING UserName;
        public UNICODE_STRING LogonDomainName;
        public UNICODE_STRING ServerName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSV1_0_GETCHALLENRESP_RESPONSE
    {
        public int MessageType;
        public LSA_STRING CaseSensitiveChallengeResponse;
        public LSA_STRING CaseInsensitiveChallengeResponse;
        public UNICODE_STRING UserName;
        public UNICODE_STRING LogonDomainName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] UserSessionKey;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] LanmanSessionKey;
    }

    internal enum TS_ASN1_PDU : uint
    {
        TsPasswordCreds = 0,
        TsSmartCardCreds,
        TsCredentials,
        TsRequest,
        TsRemoteGuardCreds,
        TsRemoteGuardInnerPacket
    }

    internal enum SPNEGO_ASN1_PDU : uint
    {
        SavedMechTypeList = 0,
        NegotiationToken,
        InitialNegToken
    }

    internal enum GSSAPI_ASN1_PDU : uint
    {
        InitialContextToken = 0,
    }

    internal enum KERB_ASN1_PDU : uint
    {
        KerbPreauthDataList = 12,
        KerbEncryptedTimestamp = 13,
        KerbEtypeInfo2 = 15,
        KerbEncryptedData = 16,
        KerbApRequest = 23,
        KerbAuthenticator = 24,
        KerbApReply = 25,
        KerbEncryptedApReply = 26,
        KerbError = 33,
        KerbPaPacRequest = 39,
        KerbTgtRequest = 76,
        KerbTgtReply = 77,
        KerbEncryptedTicket = 79,
        KerbAsReply = 82,
        KerbEncryptedAsReply = 84,
        KerbAsRequest = 97,
        KerbTgsRequest = 98,
    }

    static class Interop
    {
        public static byte[] ToRawBytes<T>(this T obj)
            where T : struct
        {
            var result = new byte[Marshal.SizeOf<T>()];
            var handle = GCHandle.Alloc(result, GCHandleType.Pinned);

            try
            {
                Marshal.StructureToPtr(obj, handle.AddrOfPinnedObject(), false);
                return result;
            }
            finally
            {
                handle.Free();
            }
        }

        public static T ToStruct<T>(this byte[] obj)
        {
            var handle = GCHandle.Alloc(obj, GCHandleType.Pinned);

            try
            {
                return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }
        }

        public static byte ParseAsn1TagNumber(byte tag)
        {
            return (byte)(tag & 0b11111);
        }

        public static T SwapEndianness<T>(T value)
            where T : unmanaged
        {
            byte[] bytes = null;

            switch (Type.GetTypeCode(typeof(T)))
            {
                case TypeCode.Int16: bytes = BitConverter.GetBytes((short)(object)value); break;
                case TypeCode.UInt16: bytes = BitConverter.GetBytes((ushort)(object)value); break;
                case TypeCode.Int32: bytes = BitConverter.GetBytes((int)(object)value); break;
                case TypeCode.UInt32: bytes = BitConverter.GetBytes((uint)(object)value); break;
                case TypeCode.Int64: bytes = BitConverter.GetBytes((long)(object)value); break;
                case TypeCode.UInt64: bytes = BitConverter.GetBytes((ulong)(object)value); break;
                default: break;
            }

            if (bytes != null)
            {
                Array.Reverse(bytes);

                switch (Type.GetTypeCode(typeof(T)))
                {
                    case TypeCode.Int16: return (T)(object)BitConverter.ToInt16(bytes, 0);
                    case TypeCode.UInt16: return (T)(object)BitConverter.ToUInt16(bytes, 0);
                    case TypeCode.Int32: return (T)(object)BitConverter.ToInt32(bytes, 0);
                    case TypeCode.UInt32: return (T)(object)BitConverter.ToUInt32(bytes, 0);
                    case TypeCode.Int64: return (T)(object)BitConverter.ToInt64(bytes, 0);
                    case TypeCode.UInt64: return (T)(object)BitConverter.ToUInt64(bytes, 0);
                    default: break;
                }
            }

            throw new NotSupportedException($"Cannot reverse endianness for type '{typeof(T).FullName}'");
        }

        [DllImport("secur32.dll", CharSet = CharSet.Auto)]
        public static extern int AcquireCredentialsHandle(string pszPrincipal, string pszPackage, uint fCredentialUse, IntPtr pvLogonId, 
            byte[] pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument, ref SEC_HANDLE phCredential, out SEC_INT ptsExpiry);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int FreeCredentialsHandle(ref SEC_HANDLE phCredential);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int InitializeSecurityContext(ref SEC_HANDLE phCredential, IntPtr phContext, string pszTargetName, uint fContextReq, uint Reserved1, 
            uint TargetDataRep, IntPtr pInput, uint Reserved2, out SEC_HANDLE phNewContext, ref SecBufferDesc pOutput, out uint pfContextAttr, out SEC_INT ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int InitializeSecurityContext(ref SEC_HANDLE phCredential, ref SEC_HANDLE phContext, string pszTargetName, uint fContextReq, uint Reserved1,
            uint TargetDataRep, ref SecBufferDesc pInput, uint Reserved2, out SEC_HANDLE phNewContext, ref SecBufferDesc pOutput, out uint pfContextAttr, out SEC_INT ptsExpiry);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int DeleteSecurityContext(ref SEC_HANDLE phContext);


        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int LsaLookupAuthenticationPackage(IntPtr LsaHandle, ref LSA_STRING PackageName, out uint AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, uint AuthenticationPackage, byte[] ProtocolSubmitBuffer, int SubmitBufferLength, out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int LsaFreeReturnBuffer(IntPtr Buffer);


        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaEnumerateLogonSessions(out int LogonSessionCount, out IntPtr LogonSessionList);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaGetLogonSessionData(IntPtr LogonId, out IntPtr ppLogonSessionData);


        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertSidToStringSid(IntPtr Sid, out IntPtr StringSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LocalFree(IntPtr hMem);


        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int ImpersonationLevel, out IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        // NTLM

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool NtlmEncodeCredIsoRemoteInput(ref NtlmCredIsoRemoteInput_CalculateNtResponse pInput, out IntPtr pvEncoded, out int pcbEncoded);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool NtlmDecodeCredIsoRemoteOutput(byte[] pbOutput, int cbOutput, out IntPtr ppDecoded);

        // TSSSP

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TsEncodeData(byte[] DataStruct, TS_ASN1_PDU Pdu, out IntPtr Buffer, out int Size);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TsDecodeData(byte[] Buffer, int Size, TS_ASN1_PDU Pdu, out IntPtr DataStruct);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TsFreeDecoded(IntPtr DataStruct, TS_ASN1_PDU Pdu);

        public static byte[] EncodeObject<T>(T structure, TS_ASN1_PDU pdu)
            where T : struct
        {
            return EncodeAsn1Object(structure, pdu, TsEncodeData);
        }

        public static DecodedObjectWrapper<T, TS_ASN1_PDU> DecodeObject<T>(byte[] bytes, TS_ASN1_PDU pdu)
            where T : struct
        {
            return DecodeAsn1Object<T, TS_ASN1_PDU>(bytes, pdu, TsDecodeData, TsFreeDecoded);
        }

        // SPNEGO

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SpnegoEncodeData(byte[] DataStruct, SPNEGO_ASN1_PDU Pdu, out IntPtr Buffer, out int Size);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SpnegoDecodeData(byte[] Buffer, int Size, SPNEGO_ASN1_PDU Pdu, out IntPtr DataStruct);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SpnegoFreeDecoded(IntPtr DataStruct, SPNEGO_ASN1_PDU Pdu);

        public static byte[] EncodeObject<T>(T structure, SPNEGO_ASN1_PDU pdu)
            where T : struct
        {
            return EncodeAsn1Object(structure, pdu, SpnegoEncodeData);
        }

        public static DecodedObjectWrapper<T, SPNEGO_ASN1_PDU> DecodeObject<T>(byte[] bytes, SPNEGO_ASN1_PDU pdu)
            where T : struct
        {
            return DecodeAsn1Object<T, SPNEGO_ASN1_PDU>(bytes, pdu, SpnegoDecodeData, SpnegoFreeDecoded);
        }

        // GSS-API

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GssApiEncodeData(byte[] DataStruct, GSSAPI_ASN1_PDU Pdu, out IntPtr Buffer, out int Size);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GssApiDecodeData(byte[] Buffer, int Size, GSSAPI_ASN1_PDU Pdu, out IntPtr DataStruct);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GssApiFreeDecoded(IntPtr DataStruct, GSSAPI_ASN1_PDU Pdu);

        public static byte[] EncodeObject<T>(T structure, GSSAPI_ASN1_PDU pdu)
            where T : struct
        {
            return EncodeAsn1Object(structure, pdu, GssApiEncodeData);
        }

        public static DecodedObjectWrapper<T, GSSAPI_ASN1_PDU> DecodeObject<T>(byte[] bytes, GSSAPI_ASN1_PDU pdu)
            where T : struct
        {
            return DecodeAsn1Object<T, GSSAPI_ASN1_PDU>(bytes, pdu, GssApiDecodeData, GssApiFreeDecoded);
        }

        // Kerberos

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool KerbEncodeData(byte[] DataStruct, KERB_ASN1_PDU Pdu, out IntPtr Buffer, out int Size);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool KerbDecodeData(byte[] Buffer, int Size, KERB_ASN1_PDU Pdu, out IntPtr DataStruct);

        [DllImport("DumpGuardLib.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool KerbFreeDecoded(IntPtr DataStruct, KERB_ASN1_PDU Pdu);

        public static byte[] EncodeObject<T>(T structure, KERB_ASN1_PDU pdu)
            where T : struct
        {
            return EncodeAsn1Object(structure, pdu, KerbEncodeData);
        }

        public static DecodedObjectWrapper<T, KERB_ASN1_PDU> DecodeObject<T>(byte[] bytes, KERB_ASN1_PDU pdu)
            where T : struct
        {
            return DecodeAsn1Object<T, KERB_ASN1_PDU>(bytes, pdu, KerbDecodeData, KerbFreeDecoded);
        }

        // Generics

        private delegate bool EncodeFunction<T>(byte[] DataStruct, T Pdu, out IntPtr Buffer, out int Size);

        private static byte[] EncodeAsn1Object<T1, T2>(T1 structure, T2 pdu, EncodeFunction<T2> encode)
            where T1 : struct
            where T2 : Enum
        {
            if (encode(structure.ToRawBytes(), pdu, out IntPtr buffer, out int size))
            {
                var bytes = new byte[size];
                Marshal.Copy(buffer, bytes, 0, size);
                return bytes;
            }

            return null;
        }

        private delegate bool DecodeFunction<T>(byte[] Buffer, int Size, T Pdu, out IntPtr Datastruct);
        public delegate bool FreeDecodedFunction<T>(IntPtr Datastruct, T Pdu);

        public class DecodedObjectWrapper<T1, T2> : IDisposable
            where T1 : struct
            where T2 : Enum
        {
            private IntPtr StructurePointer { get; set; }
            private FreeDecodedFunction<T2> FreeFunction { get; set; }

            public T1 Object { get; set; }
            private T2 Pdu { get; set; }

            public DecodedObjectWrapper(IntPtr ptr, FreeDecodedFunction<T2> free_function, T2 pdu)
            {
                StructurePointer = ptr;
                FreeFunction = free_function;

                Object = Marshal.PtrToStructure<T1>(StructurePointer);
                Pdu = pdu;
            }

            public void Dispose()
            {
                if (StructurePointer != IntPtr.Zero)
                {
                    FreeFunction(StructurePointer, Pdu);
                    StructurePointer = IntPtr.Zero;
                }
            }
        }

        private static DecodedObjectWrapper<T1, T2> DecodeAsn1Object<T1, T2>(byte[] bytes, T2 pdu, DecodeFunction<T2> decode, FreeDecodedFunction<T2> free)
            where T1 : struct
            where T2 : Enum
        {
            if (!decode(bytes, bytes.Length, pdu, out IntPtr struct_ptr))
                throw new Exception($"Failed to decode object with type = '{typeof(T1).FullName}'");

            return new DecodedObjectWrapper<T1, T2>(struct_ptr, free, pdu);
        }
    }
}
