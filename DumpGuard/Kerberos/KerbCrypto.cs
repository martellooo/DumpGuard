using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Contexts;

namespace DumpGuard.Kerberos
{
    internal class KerbCrypto
    {
        public enum KERB_KEY_USAGE : uint
        {
            AsReqPaEncTimestamp = 1,                // Encrypted with the client key (AS-REQ PA-ENC-TIMESTAMP padata timestamp)
            AsRepTgsRep = 2,                        // Encrypted with the service key (AS-REP Ticket and TGS-REP Ticket - includes TGS session key or application session key)
            AsRepEncryptedPart = 3,                 // Encrypted with the client key (AS-REP encrypted part - includes TGS session key or application session key)
            TgsReqEncAuthorizationData = 4,         // Encrypted with the TGS session key (TGS-REQ KDC-REQ-BODY AuthorizationData)
            TgsReqEncAuthorizationDataSubKey = 5,   // Encrypted with the TGS authenticator subkey (TGS-REQ KDC-REQ-BODY AuthorizationData)
            TgsReqPaAuthenticatorChecksum = 6,      // Keyed with the TGS session key (TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum)
            TgsReqPaAuthenticator = 7,              // Encrypted with the TGS session key (TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator - includes TGS authenticator subkey)
            TgsRepEncryptedPart = 8,                // Encrypted with the TGS session key (TGS-REP encrypted part - includes application session key)
            TgsRepEncryptedPartSubkey = 9,          // Encrypted with the TGS authenticator subkey (TGS-REP encrypted part - includes application session key)
            ApReqAuthenticatorChecksum = 10,        // Keyed with the application session key (AP-REQ Authenticator cksum)
            ApReqAuthenticator = 11,                // Encrypted with the application session key (AP-REQ Authenticator - includes application authenticator subkey)
            ApRepEncryptedPart = 12,                // Encrypted with the application session key (AP-REP encrypted part - includes application session subkey)
            KrbPrivEncryptedPart = 13,              // Encrypted with a key chosen by the application (KRB-PRIV encrypted part)
            KrbCredEncryptedPart = 14,              // Encrypted with a key chosen by the application (KRB-CRED encrypted part)
            KrbSafeChecksum = 15,                   // Keyed with a key chosen by the application (KRB-SAFE cksum)
            KrbNonKerbSalt = 16,                    // 
            KrbNonKeyChecksumSalt = 17,             // 
            KgUsageAcceptorSeal = 22,               // Used for Kerberos v5 GSS-API Wrap tokens (server)
            KgUsageAcceptorSign = 23,               // Used for Kerberos v5 GSS-API MIC tokens (server)
            KgUsageInitiatorSeal = 24,              // Used for Kerberos v5 GSS-API Wrap tokens (client)
            KgUsageInitiatorSign = 25,              // Used for Kerberos v5 GSS-API MIC tokens (client)
        }

        public enum KERB_CTYPE : uint
        {
            None = 0,
            kerb_crc32 = 1,
            md4 = 2,
            des_mac_1510 = 4,
            des_mac_k = 5,
            md5 = 7,
            hmac_sha_96_aes128 = 15,
            hmac_sha_96_aes256 = 16,
            sha = 0xffffff7d,
            crc32 = 0xffffff7c,
            des_mac = 0xffffff7b,
            des_mac_md5 = 0xffffff7a,
            md25 = 0xffffff79,
            md5_hmac = 0xffffff77,
            hmac_md5 = 0xffffff76,
            hmac_sha_96_aes128_ki = 0xffffff6a,
            hmac_sha_96_aes256_ki = 0xffffff69,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ECHECKSUM
        {
            public KERB_CTYPE Type;
            public int Size;
            public int Reserved1;
            public int Reserved2;
            private readonly IntPtr Initialize;
            private readonly IntPtr Sum;
            private readonly IntPtr Finalize;
            private readonly IntPtr Finish;
            private readonly IntPtr InitializeEx;
            private readonly IntPtr InitializeEx2;

            // Delegates

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_CHECKSUM_Initialize([MarshalAs(UnmanagedType.Bool)] bool fReserved, out IntPtr Context);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_CHECKSUM_Sum(IntPtr Context, int Size, byte[] Buffer);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_CHECKSUM_Finalize(IntPtr Context, byte[] Buffer);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_CHECKSUM_Finish(ref IntPtr Context);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_CHECKSUM_InitializeEx(byte[] Key, int KeySize, KERB_KEY_USAGE KeyUsage, out IntPtr Context);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_CHECKSUM_InitializeEx2(byte[] Key, int KeySize, byte[] Seed, KERB_KEY_USAGE KeyUsage, out IntPtr Context);

            // Invokers

            public int InvokeInitialize(bool fReserved, out IntPtr Context) =>
                Marshal.GetDelegateForFunctionPointer<KERB_CHECKSUM_Initialize>(Initialize)(fReserved, out Context);

            public int InvokeSum(IntPtr Context, int Size, byte[] Buffer) =>
                Marshal.GetDelegateForFunctionPointer<KERB_CHECKSUM_Sum>(Sum)(Context, Size, Buffer);

            public int InvokeFinalize(IntPtr Context, byte[] Buffer) =>
                Marshal.GetDelegateForFunctionPointer<KERB_CHECKSUM_Finalize>(Finalize)(Context, Buffer);

            public int InvokeFinish(ref IntPtr Context) =>
                Marshal.GetDelegateForFunctionPointer<KERB_CHECKSUM_Finish>(Finish)(ref Context);

            public int InvokeInitializeEx(byte[] Key, int KeySize, KERB_KEY_USAGE KeyUsage, out IntPtr Context) =>
                Marshal.GetDelegateForFunctionPointer<KERB_CHECKSUM_InitializeEx>(InitializeEx)(Key, KeySize, KeyUsage, out Context);

            public int InvokeInitializeEx2(byte[] Key, int KeySize, byte[] Seed, KERB_KEY_USAGE KeyUsage, out IntPtr Context) =>
                Marshal.GetDelegateForFunctionPointer<KERB_CHECKSUM_InitializeEx2>(InitializeEx2)(Key, KeySize, Seed, KeyUsage, out Context);
        }

        public enum KERB_ETYPE : uint
        {
            None = 0,
            des_crc32 = 1,                      // Kerberos DES-CBC-CRC
            des_md5 = 3,                        // Kerberos DES-CBC-MD5
            aes128 = 17,                        // Kerberos AES128-CTS-HMAC-SHA1-96
            aes256 = 18,                        // Kerberos AES256-CTS-HMAC-SHA1-96
            rc4_hmac = 23,                      // RSADSI RC4-HMAC
            rc4_hmac_exp = 24,                  // RSADSI RC4-HMAC
            rc4_md4 = 0xffffff80,               // RSADSI RC4-MD4
            des_plain = 0xffffff7c,             // Kerberos DES-Plain
            rc4_hmac_old = 0xffffff7b,          // RSADSI RC4-HMAC
            rc4_plain_old = 0xffffff7a,         // RSADSI RC4
            rc4_hmac_old_exp = 0xffffff79,      // RSADSI RC4-HMAC
            rc4_plain_old_exp = 0xffffff78,     // RSADSI RC4-EXP
            rc4_plain = 0xffffff74,             // RSADSI RC4
            rc4_plain_exp = 0xffffff73,         // RSADSI RC4-EXP
            aes128_plain = 0xffffff6c,          // Kerberos AES128-CTS-HMAC-SHA1-96-PLAIN
            aes256_plain = 0xffffff6b,          // Kerberos AES256-CTS-HMAC-SHA1-96-PLAIN
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ECRYPT
        {
            public KERB_ETYPE Type;
            public int BlockSize;
            public int Reserved1; // Duplicate of Type (?)
            public int KeySize;
            public int MetaSize;
            private readonly uint Reserved2;
            private readonly uint Reserved3;
            private readonly uint Reserved4;
            [MarshalAs(UnmanagedType.LPWStr)] public string AlgorithmName;
            private readonly IntPtr Initialize;
            private readonly IntPtr Encrypt;
            private readonly IntPtr Decrypt;
            private readonly IntPtr Finish;
            private readonly IntPtr HashPassword;
            private readonly IntPtr RandomKey;
            private readonly IntPtr Control;
            private readonly IntPtr EncryptPlain;
            private readonly IntPtr DecryptPlain;
            private readonly IntPtr PsuedoRandomFunction;
            private readonly IntPtr PseudoRandomFunctionPlus;

            // Delegates

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_ECRYPT_Initialize(byte[] Key, int KeySize, KERB_KEY_USAGE KeyUsage, out IntPtr Context);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_ECRYPT_Crypt(IntPtr Context, byte[] Input, int InputSize, byte[] Output, ref int OutputSize);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_ECRYPT_Finish(ref IntPtr Context);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int PKERB_ECRYPT_HashPassword(ref UNICODE_STRING Password, UNICODE_STRING Salt, int IterationCount, byte[] Output);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_ECRYPT_RandomKey(IntPtr Key, uint KeySize, byte[] Output);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_ECRYPT_Control([MarshalAs(UnmanagedType.Bool)] bool fReserved, IntPtr Context, byte[] Input, int InputSize);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate int KERB_ECRYPT_Crypt_Plain(IntPtr Context, int ExtraLength, int DataSize, byte[] Data);

            // Invokers

            public int InvokeInitialize(byte[] Key, int KeySize, KERB_KEY_USAGE KeyUsage, out IntPtr Context) =>
                Marshal.GetDelegateForFunctionPointer<KERB_ECRYPT_Initialize>(Initialize)(Key, KeySize, KeyUsage, out Context);

            public int InvokeEncrypt(IntPtr Context, byte[] Input, int InputSize, byte[] Output, ref int OutputSize) =>
                Marshal.GetDelegateForFunctionPointer<KERB_ECRYPT_Crypt>(Encrypt)(Context, Input, InputSize, Output, ref OutputSize);

            public int InvokeDecrypt(IntPtr Context, byte[] Input, int InputSize, byte[] Output, ref int OutputSize) =>
                Marshal.GetDelegateForFunctionPointer<KERB_ECRYPT_Crypt>(Decrypt)(Context, Input, InputSize, Output, ref OutputSize);

            public int InvokeFinish(ref IntPtr Context) =>
                Marshal.GetDelegateForFunctionPointer<KERB_ECRYPT_Finish>(Finish)(ref Context);

            public int InvokeHashPassword(UNICODE_STRING Password, UNICODE_STRING Salt, int IterationCount, byte[] Output) =>
                Marshal.GetDelegateForFunctionPointer<PKERB_ECRYPT_HashPassword>(HashPassword)(ref Password, Salt, IterationCount, Output);

            public int InvokeRandomKey(IntPtr Key, uint KeySize, byte[] Output) =>
                Marshal.GetDelegateForFunctionPointer<KERB_ECRYPT_RandomKey>(RandomKey)(Key, KeySize, Output);

            public int InvokeControl(bool fReserved, IntPtr Context, byte[] Input, int InputSize) =>
                Marshal.GetDelegateForFunctionPointer<KERB_ECRYPT_Control>(Control)(fReserved, Context, Input, InputSize);

            public int InvokeEncryptPlain(IntPtr Context, int TrailerSize, int DataSize, byte[] Data) =>
                Marshal.GetDelegateForFunctionPointer<KERB_ECRYPT_Crypt_Plain>(EncryptPlain)(Context, TrailerSize, DataSize, Data);

            public int InvokeDecryptPlain(IntPtr Context, int TrailerSize, int DataSize, byte[] Data) =>
                Marshal.GetDelegateForFunctionPointer<KERB_ECRYPT_Crypt_Plain>(DecryptPlain)(Context, TrailerSize, DataSize, Data);
        }

        [DllImport("cryptdll.dll", SetLastError = true)]
        public static extern int CDLocateCSystem(KERB_ETYPE eType, out IntPtr Engine);

        [DllImport("cryptdll.dll", SetLastError = true)]
        public static extern int CDLocateCheckSum(KERB_CTYPE cType, out IntPtr Checksum);

        public static byte[] KerbHashPassword(KERB_ETYPE eType, string password, string salt, int iterations = 4096)
        {
            if (CDLocateCSystem(eType, out IntPtr engine) < 0)
                throw new Exception($"Could not locate crypto system for encryption type '{eType}'");

            var crypto_system = Marshal.PtrToStructure<KERB_ECRYPT>(engine);
            var output = new byte[crypto_system.KeySize];
            var status = 0;

            if ((status = crypto_system.InvokeHashPassword(new UNICODE_STRING(password), new UNICODE_STRING(salt), iterations, output)) < 0)
                throw new Exception($"Failed to hash password '{password}' with error: {status:x}");
         
            return output;
        }

        public static byte[] KerbChecksumData(KERB_CTYPE cType, KERB_KEY_USAGE KeyUsage, byte[] Key, IEnumerable<byte[]> DataBuffers)
        {
            if (CDLocateCheckSum(cType, out IntPtr checksum) < 0)
                throw new Exception($"Could not locate checksum system for checksum type '{cType}'");

            var checksum_system = Marshal.PtrToStructure<KERB_ECHECKSUM>(checksum);
            var status = 0;

            if ((status = checksum_system.InvokeInitializeEx(Key, Key.Length, KeyUsage, out IntPtr context)) < 0)
                throw new Exception($"Failed to initialize checksum system for checksum type '{cType}' with error: {status:x}");

            foreach (var data_buffer in DataBuffers)
            {
                if ((status = checksum_system.InvokeSum(context, data_buffer.Length, data_buffer)) < 0)
                    throw new Exception($"Failed to sum checksum with error: {status:x}");
            }

            var output = new byte[checksum_system.Size];

            if ((status = checksum_system.InvokeFinalize(context, output)) < 0)
                throw new Exception($"Failed to finalize checksum with error: {status:x}");

            if ((status = checksum_system.InvokeFinish(ref context)) < 0)
                throw new Exception($"Failed to finish checksum with error: {status:x}");
        
            return output;
        }

        public static byte[] KerbEncryptData(KERB_ETYPE eType, KERB_KEY_USAGE KeyUsage, byte[] Key, byte[] Data, bool Control = false)
        {
            return KerbTransformData(eType, KeyUsage, Key, Data, Control, true);
        }

        public static byte[] KerbDecryptData(KERB_ETYPE eType, KERB_KEY_USAGE KeyUsage, byte[] Key, byte[] Data, bool Control = false)
        {
            return KerbTransformData(eType, KeyUsage, Key, Data, Control, false);
        }

        private static byte[] KerbTransformData(KERB_ETYPE eType, KERB_KEY_USAGE KeyUsage, byte[] Key, byte[] Data, bool Control, bool EncryptOrDecrypt)
        {
            if (CDLocateCSystem(eType, out IntPtr engine) < 0)
                throw new Exception($"Could not locate crypto system for encryption type '{eType}'");

            var crypto_system = Marshal.PtrToStructure<KERB_ECRYPT>(engine);
            var status = 0;

            if (crypto_system.KeySize != Key.Length)
                throw new Exception($"Tried to call crypto system with key-size '{crypto_system.KeySize}' with a key of size '{Key.Length}'");
            
            if ((status = crypto_system.InvokeInitialize(Key, Key.Length, KeyUsage, out IntPtr context)) < 0)
                throw new Exception($"Failed to initialize crypto system for encryption type '{eType}' with error: {status:x}");

            if (Control)
            {
                if ((status = crypto_system.InvokeControl(true, context, Data, Data.Length)) < 0)
                    throw new Exception($"Failed to crypto control with error: {status:x}");
            }

            var output_size = Data.Length;
            var output_mod = output_size % crypto_system.BlockSize;

            if (output_mod != 0)
                output_size += crypto_system.BlockSize - output_mod;

            output_size += crypto_system.MetaSize;

            var output = new byte[output_size];

            if (EncryptOrDecrypt)
                status = crypto_system.InvokeEncrypt(context, Data, Data.Length, output, ref output_size);
            else
                status = crypto_system.InvokeDecrypt(context, Data, Data.Length, output, ref output_size);

            if (status < 0)
                throw new Exception($"Failed to {(EncryptOrDecrypt ? "encrypt" : "decrypt")} with error: {status:x}");

            if ((status = crypto_system.InvokeFinish(ref context)) < 0)
                throw new Exception($"Failed to finish {(EncryptOrDecrypt ? "encryption" : "decryption")} with error: {status:x}");

            return output.Take(output_size).ToArray();
        }
    }
}
