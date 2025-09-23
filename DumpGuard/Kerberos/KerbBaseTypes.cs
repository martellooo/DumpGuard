using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using static DumpGuard.Kerberos.KerbCrypto;

namespace DumpGuard.Kerberos
{
    internal class KerbBaseTypes
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ETYPE_WRAPPER
        {
            public KERB_ETYPE Type;

            public KERB_ETYPE_WRAPPER(KERB_ETYPE type)
            {
                Type = type;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_PA_PAC_REQUEST
        {
            public byte IncludePac;

            public KERB_PA_PAC_REQUEST(bool include_pac)
            {
                IncludePac = Convert.ToByte(include_pac);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_AUTHORIZATION_DATA
        {
            public int AuthDataType;
            public OCTET_STRING AuthData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TRANSITED_ENCODING
        {
            public int TransitedType;
            public OCTET_STRING Contents;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_LAST_REQUEST
        {
            public int LastRequestType;
            public KERB_TIME LastRequestValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CHECKSUM
        {
            public int ChecksumType;
            public OCTET_STRING Checksum;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_PREAUTH_DATA_LIST
        {
            public LinkedList<KERB_PA_DATA> List;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TIME
        {
            public ushort Year;
            public byte Month;
            public byte Day;
            public byte Hour;
            public byte Minute;
            public byte Second;
            public ushort Millisecond;
            public byte Universal; // bool
            public ushort Diff;

            public KERB_TIME(DateTime time, byte universal = 1, ushort difference = 0)
            {
                Year = (ushort)time.Year;
                Month = (byte)time.Month;
                Day = (byte)time.Day;
                Hour = (byte)time.Hour;
                Minute = (byte)time.Minute;
                Second = (byte)time.Second;
                Millisecond = (ushort)time.Millisecond;
                Universal = universal;
                Diff = difference;
            }

            public KERB_TIME(KERB_TIME other)
                : this(new DateTime(other.Year, other.Month, other.Day, other.Hour, 
                    other.Minute, other.Second, other.Millisecond), other.Universal, other.Diff)
            {

            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_HOST_ADDRESS_ENTRY : IDisposable
        {
            public int AddressType;
            public OCTET_STRING Address;

            public KERB_HOST_ADDRESS_ENTRY(int type, byte[] bytes)
            {
                AddressType = type;
                Address = new OCTET_STRING(bytes);
            }

            public KERB_HOST_ADDRESS_ENTRY(KERB_HOST_ADDRESS_ENTRY other)
                : this(other.AddressType, other.Address.ToBytes())
            {

            }

            public void Dispose()
            {
                Address.Dispose();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_EXTENSION_ENTRY : IDisposable
        {
            public int TicketExtensionType;
            public OCTET_STRING TicketExtensionData;

            public KERB_TICKET_EXTENSION_ENTRY(int type, byte[] bytes)
            {
                TicketExtensionType = type;
                TicketExtensionData = new OCTET_STRING(bytes);
            }

            public KERB_TICKET_EXTENSION_ENTRY(KERB_TICKET_EXTENSION_ENTRY other)
                : this(other.TicketExtensionType, other.TicketExtensionData.ToBytes())
            {

            }

            public void Dispose()
            {
                TicketExtensionData.Dispose();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ENCRYPTION_KEY : IDisposable
        {
            public KERB_ETYPE KeyType;
            public OCTET_STRING KeyValue;

            public KERB_ENCRYPTION_KEY(KERB_ETYPE key_type, byte[] key)
            {
                KeyType = key_type;
                KeyValue = new OCTET_STRING(key);
            }

            public KERB_ENCRYPTION_KEY(KERB_ENCRYPTION_KEY other)
                : this(other.KeyType, other.KeyValue.ToBytes())
            {

            }

            public void Dispose()
            {
                KeyValue.Dispose();
            }
        }

        [Flags]
        public enum KERB_ENCRYPTED_TIMESTAMP_FLAGS : ushort
        {
            None = 0,
            Usec = 0x80
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ENCRYPTED_TIMESTAMP
        {
            public KERB_ENCRYPTED_TIMESTAMP_FLAGS Flags;
            public KERB_TIME Timestamp;
            public int Usec;

            public KERB_ENCRYPTED_TIMESTAMP(DateTime timeutc)
            {
                Flags = KERB_ENCRYPTED_TIMESTAMP_FLAGS.None;
                Timestamp = new KERB_TIME(timeutc);
                Usec = 0;
            }

            public KERB_ENCRYPTED_TIMESTAMP(DateTime timeutc, int microseconds)
                : this(timeutc)
            {
                Flags |= KERB_ENCRYPTED_TIMESTAMP_FLAGS.Usec;
                Usec = microseconds;
            }
        }

        [Flags]
        public enum KERB_ENCRYPTED_DATA_FLAGS : ushort
        {
            None = 0,
            Version = 0x80
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ENCRYPTED_DATA : IDisposable
        {
            public KERB_ENCRYPTED_DATA_FLAGS Flags;
            public KERB_ETYPE EncryptionType;
            public int Version;
            public OCTET_STRING CipherText;

            public KERB_ENCRYPTED_DATA(KERB_ETYPE type, byte[] bytes)
            {
                Flags = KERB_ENCRYPTED_DATA_FLAGS.None;
                EncryptionType = type;
                Version = 0;
                CipherText = new OCTET_STRING(bytes);
            }

            public KERB_ENCRYPTED_DATA(KERB_ETYPE type, int version, byte[] bytes)
                : this(type, bytes)
            {
                Flags |= KERB_ENCRYPTED_DATA_FLAGS.Version;
                Version = version;
            }

            public KERB_ENCRYPTED_DATA(KERB_ENCRYPTED_DATA other)
                : this(other.EncryptionType, other.Version, other.CipherText.ToBytes())
            {
                Flags = other.Flags;
            }

            public void Dispose()
            {
                CipherText.Dispose();
            }

            public byte[] Decrypt(KERB_KEY_USAGE key_usage, Dictionary<KERB_ETYPE, byte[]> keys)
            {
                return KerbDecryptData(EncryptionType, key_usage, keys[EncryptionType], CipherText.ToBytes());
            }

            public byte[] Decrypt(KERB_KEY_USAGE key_usage, KERB_ETYPE key_type, byte[] key)
            {
                if (key_type != EncryptionType)
                    throw new ArgumentException($"Attempted to decrypt a {EncryptionType} blob using a key for {key_type}");

                return KerbDecryptData(key_type, key_usage, key, CipherText.ToBytes());
            }
        }

        public enum KERB_PRINCIPAL_NAME_TYPE
        {
            NT_UNKNOWN = 0,
            NT_PRINCIPAL = 1,
            NT_SRV_INST = 2,
            NT_SRV_HST = 3,
            NT_SRV_XHST = 4,
            NT_UID = 5,
            NT_X500_PRINCIPAL = 6,
            NT_SMTP_NAME = 7,
            NT_ENTERPRISE = 10,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_PRINCIPAL_NAME : IDisposable
        {
            public KERB_PRINCIPAL_NAME_TYPE NameType;
            public LinkedList<UnmanagedAnsiString> NameString;

            public KERB_PRINCIPAL_NAME(KERB_PRINCIPAL_NAME_TYPE type, IEnumerable<UnmanagedAnsiString> strings)
            {
                NameType = type;
                NameString = new LinkedList<UnmanagedAnsiString>(strings);
            }

            public KERB_PRINCIPAL_NAME(KERB_PRINCIPAL_NAME_TYPE type, IEnumerable<string> strings)
                : this(type, strings?.Select(s => new UnmanagedAnsiString(s)))
            {

            }

            public KERB_PRINCIPAL_NAME(KERB_PRINCIPAL_NAME_TYPE type, params string[] strings)
                : this(type, (IEnumerable<string>)strings)
            {

            }

            public KERB_PRINCIPAL_NAME(KERB_PRINCIPAL_NAME other)
                : this(other.NameType, other.NameString.ParseList())
            {

            }

            public void Dispose()
            {
                NameString.Dispose();
            }
        }

        public enum KERB_PA_DATA_TYPE : uint
        {
            PA_TGS_REQ = 1,
            PA_ENC_TIMESTAMP = 2,
            PA_PW_SALT = 3,
            PA_ENC_UNIX_TIME = 5,
            PA_SANDIA_SECURE_ID = 6,
            PA_SESAME = 7,
            PA_OSF_DCE = 8,
            PA_CYBERSAFE_SECURE_ID = 9,
            PA_AFS3_SALT = 10,
            PA_ETYPE_INFO = 11,
            PA_SAM_CHALLENGE = 12,
            PA_SAM_RESPONSE = 13,
            PA_PK_AS_REQ_OLD = 14,
            PA_PK_AS_REP_OLD = 15,
            PA_PK_AS_REQ = 16,
            PA_PK_AS_REP = 17,
            PA_PK_OCSP_RESPONSE = 18,
            PA_ETYPE_INFO2 = 19,
            PA_USE_SPECIFIED_KVNO = 20,
            PA_SVR_REFERRALINFO = 20,
            PA_SAM_REDIRECT = 21,
            PA_GET_FROM_TYPED_DATA = 22,
            PA_SAM_ETYPE_INFO = 23,
            PA_ALT_PRINC = 24,
            PA_SERVER_REFERRAL_INFO = 25,
            PA_SAM_CHALLENGE2 = 30,
            PA_SAM_RESPONSE2 = 31,
            PA_EXTRA_TGT = 41,
            TD_PKINIT_CMS_CERTIFICATES = 101,
            TD_KRB_PRINCIPAL = 102,
            TD_KRB_REALM = 103,
            TD_TRUSTED_CERTIFIERS = 104,
            TD_CERTIFICATE_INDEX = 105,
            TD_APP_DEFINED_ERROR = 106,
            TD_REQ_NONCE = 106,
            TD_REQ_SEQ = 107,
            PA_PAC_REQUEST = 128,
            S4U_SELF = 129,
            PA_S4U_X509_USER = 130,
            PA_FX_COOKIE = 133,
            PA_FX_FAST = 136,
            PA_FX_ERROR = 137,
            PA_ENCRYPTED_CHALLENGE = 138,
            KERB_KEY_LIST_REQ = 161,
            KERB_KEY_LIST_REP = 162,
            PA_SUPPORTED_ENC_TYPES = 165,
            PA_PAC_OPTIONS = 167,
            SUPERSEDED_BY_USER = 170,
            DMSA_KEY_PACKAGE = 171,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_PA_DATA : IDisposable
        {
            public KERB_PA_DATA_TYPE PreauthDataType;
            public OCTET_STRING PreauthData;

            public KERB_PA_DATA(KERB_PA_DATA_TYPE type, byte[] bytes)
            {
                PreauthDataType = type;
                PreauthData = new OCTET_STRING(bytes);
            }

            public KERB_PA_DATA(KERB_PA_DATA other)
                : this(other.PreauthDataType, other.PreauthData.ToBytes())
            {

            }

            public void Dispose()
            {
                PreauthData.Dispose();
            }
        }

        [Flags]
        public enum KERB_TICKET_OPTIONS : uint
        {
            Reserved0               = 0b00000000000000000000000000000001,
            Forwardable             = 0b00000000000000000000000000000010,
            Forwarded               = 0b00000000000000000000000000000100,
            Proxiable               = 0b00000000000000000000000000001000,
            Proxy                   = 0b00000000000000000000000000010000,
            MayPostDate             = 0b00000000000000000000000000100000,
            PostDated               = 0b00000000000000000000000001000000,
            Reserved7               = 0b00000000000000000000000010000000,
            Renewable               = 0b00000000000000000000000100000000,
            Initial                 = 0b00000000000000000000001000000000,
            PreAuthent              = 0b00000000000000000000010000000000,
            HardwareAuthent         = 0b00000000000000000000100000000000,
            TransitedPolicyChecked  = 0b00000000000000000001000000000000,
            OkAsDelegate            = 0b00000000000000000010000000000000,
        }

        [Flags]
        public enum KERB_ENCRYPTED_TICKET_FLAGS : ushort
        {
            None = 0,
            StartTime = 0x80,
            RenewUntil = 0x40,
            ClientAddresses = 0x20,
            AuthorizationData = 0x10
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ENCRYPTED_TICKET
        {
            public KERB_ENCRYPTED_TICKET_FLAGS Flags;
            public BIT_STRING TicketFlags;
            public KERB_ENCRYPTION_KEY Key;
            [MarshalAs(UnmanagedType.LPStr)] public string Realm;
            public KERB_PRINCIPAL_NAME ClientName;
            public KERB_TRANSITED_ENCODING Transited;
            public KERB_TIME AuthTime;
            public KERB_TIME StartTime;
            public KERB_TIME EndTime;
            public KERB_TIME RenewUntil;
            public LinkedList<KERB_HOST_ADDRESS_ENTRY> ClientAddresses;
            public LinkedList<KERB_AUTHORIZATION_DATA> AuthorizationData;
        }

        [Flags]
        public enum KERB_TICKET_FLAGS : ushort
        {
            None = 0,
            TicketExtensions = 0x80
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET : IDisposable
        {
            public KERB_TICKET_FLAGS Flags;
            public int TicketVersion;
            [MarshalAs(UnmanagedType.LPStr)] public string Realm;
            public KERB_PRINCIPAL_NAME ServerName;
            public KERB_ENCRYPTED_DATA EncryptedPart;
            public LinkedList<KERB_TICKET_EXTENSION_ENTRY> TicketExtensions;

            public KERB_TICKET(int ticket_version, string realm, KERB_PRINCIPAL_NAME server_name, KERB_ENCRYPTED_DATA encrypted_part, IEnumerable<KERB_TICKET_EXTENSION_ENTRY> ticket_extensions)
            {
                Flags = KERB_TICKET_FLAGS.None;
                TicketVersion = ticket_version;
                Realm = realm;
                ServerName = new KERB_PRINCIPAL_NAME(server_name);
                EncryptedPart = new KERB_ENCRYPTED_DATA(encrypted_part);
                TicketExtensions = new LinkedList<KERB_TICKET_EXTENSION_ENTRY>(ticket_extensions);

                if (TicketExtensions.Head != IntPtr.Zero)
                    Flags |= KERB_TICKET_FLAGS.TicketExtensions;
            }

            public KERB_TICKET(KERB_TICKET other)
                : this(other.TicketVersion, other.Realm, other.ServerName, other.EncryptedPart, other.TicketExtensions.ParseList())
            {

            }

            public void Dispose()
            {
                ServerName.Dispose();
                EncryptedPart.Dispose();
                TicketExtensions.Dispose();
            }
        }

        public enum KERB_MESSAGE_TYPE : int
        {
            KrbAsReq = 10,
            KrbAsRep,
            KrbTgsReq,
            KrbTgsRep,
            KrbApReq,
            KrbApRep,
            KrbTgtReqU2U,
            KrbTgtRepU2U,

            KrbSafe = 20,
            KrbPriv,
            KrbCred,
            
            KrbError = 30,
        }

        [Flags]
        public enum KERB_AUTHENTICATOR_FLAGS : ushort
        {
            Checksum = 0x80,
            SubKey = 0x40,
            SequenceNumber = 0x20,
            AuthorizationData = 0x10
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_AUTHENTICATOR
        {
            public KERB_AUTHENTICATOR_FLAGS Flags;
            public int AuthenticatorVersion;
            [MarshalAs(UnmanagedType.LPStr)] public string ClientRealm;
            public KERB_PRINCIPAL_NAME ClientName;
            public KERB_CHECKSUM Checksum;
            public int ClientUsec;
            public KERB_TIME ClientTime;
            public KERB_ENCRYPTION_KEY SubKey;
            public OCTET_STRING SequenceNumber;
            public LinkedList<KERB_AUTHORIZATION_DATA> AuthorizationData;
        }

        [Flags]
        public enum KERB_AP_REQUEST_OPTIONS : uint
        {
            Reserved0               = 0b00000000000000000000000000000001,
            UseSessionKey           = 0b00000000000000000000000000000010,
            MutualRequired          = 0b00000000000000000000000000000100,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_AP_REQUEST
        {
            public int Version;
            public KERB_MESSAGE_TYPE MessageType;
            public BIT_STRING ApOptions;
            public KERB_TICKET Ticket;
            public KERB_ENCRYPTED_DATA Authenticator;
        }

        [Flags]
        public enum KERB_ENCRYPTED_AP_REPLY_FLAGS : ushort
        {
            None = 0,
            SubKey = 0x80,
            SequenceNumber = 0x40,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ENCRYPTED_AP_REPLY : IDisposable
        {
            public KERB_ENCRYPTED_AP_REPLY_FLAGS Flags;
            public KERB_TIME ClientTime;
            public int ClientUsec;
            public KERB_ENCRYPTION_KEY SubKey;
            public uint SequenceNumber;

            public KERB_ENCRYPTED_AP_REPLY(KERB_TIME client_time, int client_usec, KERB_ETYPE subkey_type, byte[] subkey, uint? sequence_number = null)
            {
                Flags = KERB_ENCRYPTED_AP_REPLY_FLAGS.None;
                ClientTime = new KERB_TIME(client_time);
                ClientUsec = client_usec;

                if (subkey == null)
                    SubKey = default;
                else
                {
                    Flags |= KERB_ENCRYPTED_AP_REPLY_FLAGS.SubKey;
                    SubKey = new KERB_ENCRYPTION_KEY(subkey_type, subkey);
                }

                if (sequence_number == null)
                    SequenceNumber = default;
                else
                {
                    Flags |= KERB_ENCRYPTED_AP_REPLY_FLAGS.SequenceNumber;
                    SequenceNumber = sequence_number.Value;
                }
            }

            public void Dispose()
            {
                SubKey.Dispose();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_AP_REPLY : IDisposable
        {
            public int Version;
            public KERB_MESSAGE_TYPE MessageType;
            public KERB_ENCRYPTED_DATA EncryptedPart;

            public KERB_AP_REPLY(KERB_MESSAGE_TYPE message_type, KERB_ENCRYPTED_DATA encrypted_part)
            {
                Version = 5;
                MessageType = message_type;
                EncryptedPart = new KERB_ENCRYPTED_DATA(encrypted_part);
            }

            public void Dispose()
            {
                EncryptedPart.Dispose();
            }
        }

        [Flags]
        public enum KERB_TGT_REQUEST_FLAGS : ushort
        {
            ServerName = 0x80,
            Realm = 0x40,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TGT_REQUEST
        {
            public KERB_TGT_REQUEST_FLAGS Flags;
            public int Version;
            public KERB_MESSAGE_TYPE MessageType;
            public KERB_PRINCIPAL_NAME ServerName;
            [MarshalAs(UnmanagedType.LPStr)] public string ServerRealm;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TGT_REPLY : IDisposable
        {
            public int Version;
            public KERB_MESSAGE_TYPE MessageType;
            public KERB_TICKET Ticket;

            public KERB_TGT_REPLY(KERB_MESSAGE_TYPE message_type, KERB_TICKET ticket)
            {
                Version = 5;
                MessageType = message_type;
                Ticket = new KERB_TICKET(ticket);
            }

            public void Dispose()
            {
                Ticket.Dispose();
            }
        }

        [Flags]
        public enum KERB_KDC_OPTIONS : uint
        {
            Reserved0               = 0b00000000000000000000000000000001,
            Forwardable             = 0b00000000000000000000000000000010,
            Forwarded               = 0b00000000000000000000000000000100,
            Proxiable               = 0b00000000000000000000000000001000,
            Proxy                   = 0b00000000000000000000000000010000,
            AllowPostDate           = 0b00000000000000000000000000100000,
            PostDated               = 0b00000000000000000000000001000000,
            Reserved7               = 0b00000000000000000000000010000000,
            Renewable               = 0b00000000000000000000000100000000,
            Reserved9               = 0b00000000000000000000001000000000,
            Reserved10              = 0b00000000000000000000010000000000,
            OptHardwareAuth         = 0b00000000000000000000100000000000,
            Reserved12              = 0b00000000000000000001000000000000,
            Reserved13              = 0b00000000000000000010000000000000,
            ConstrainedDelegation   = 0b00000000000000000100000000000000,
            Canonicalize            = 0b00000000000000001000000000000000,
            RequestAnonymous        = 0b00000000000000010000000000000000,
            Reserved17              = 0b00000000000000100000000000000000,
            Reserved18              = 0b00000000000001000000000000000000,
            Reserved19              = 0b00000000000010000000000000000000,
            Reserved20              = 0b00000000000100000000000000000000,
            Reserved21              = 0b00000000001000000000000000000000,
            Reserved22              = 0b00000000010000000000000000000000,
            Reserved23              = 0b00000000100000000000000000000000,
            Reserved24              = 0b00000001000000000000000000000000,
            Reserved25              = 0b00000010000000000000000000000000,
            DisabledTransitedCheck  = 0b00000100000000000000000000000000,
            RenewableOk             = 0b00001000000000000000000000000000,
            EnctktInSkey            = 0b00010000000000000000000000000000,
            Reserved29              = 0b00100000000000000000000000000000,
            Renew                   = 0b01000000000000000000000000000000,
            Validate                = 0b10000000000000000000000000000000,
        }

        [Flags]
        public enum KERB_KDC_REQUEST_BODY_FLAGS : ushort
        {
            None = 0,
            ClientName = 0x80,
            ServerName = 0x40,
            StartTime = 0x20,
            RenewUntil = 0x10,
            Addresses = 0x08,
            EncAuthorizationData = 0x04,
            AdditionalTickets = 0x02
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_KDC_REQUEST_BODY : IDisposable
        {
            public KERB_KDC_REQUEST_BODY_FLAGS Flags;
            public BIT_STRING KdcOptions;
            public KERB_PRINCIPAL_NAME ClientName;
            [MarshalAs(UnmanagedType.LPStr)] public string Realm;
            public KERB_PRINCIPAL_NAME ServerName;
            public KERB_TIME StartTime;
            public KERB_TIME EndTime;
            public KERB_TIME RenewUntil;
            public int Nonce;
            public LinkedList<KERB_ETYPE_WRAPPER> EncryptionType;
            public LinkedList<KERB_HOST_ADDRESS_ENTRY> Addresses;
            public KERB_ENCRYPTED_DATA EncAuthorizationData;
            public LinkedList<KERB_TICKET> AdditionalTickets;

            public KERB_KDC_REQUEST_BODY(KERB_KDC_OPTIONS kdc_options, string username, string domain, string service,
                DateTime? start_time, DateTime end_time, DateTime? renew_until, IEnumerable<KERB_ETYPE> encryption_types,
                IEnumerable<KERB_HOST_ADDRESS_ENTRY> addresses, KERB_ENCRYPTED_DATA? enc_authorization_data, IEnumerable<KERB_TICKET> additional_tickets)
            {

                Flags = KERB_KDC_REQUEST_BODY_FLAGS.None;
                KdcOptions = new BIT_STRING((uint)kdc_options);

                if (string.IsNullOrEmpty(username))
                    ClientName = default;
                else
                {
                    Flags |= KERB_KDC_REQUEST_BODY_FLAGS.ClientName;
                    ClientName = new KERB_PRINCIPAL_NAME(KERB_PRINCIPAL_NAME_TYPE.NT_PRINCIPAL, username.Split('/'));
                }

                if (string.IsNullOrEmpty(domain))
                    throw new ArgumentException("KERB_KDC_REQUEST_BODY must specify a domain");
                else
                    Realm = domain;

                if (string.IsNullOrEmpty(service))
                {
                    Flags |= KERB_KDC_REQUEST_BODY_FLAGS.ServerName;
                    ServerName = new KERB_PRINCIPAL_NAME(KERB_PRINCIPAL_NAME_TYPE.NT_SRV_INST, "krbtgt", domain);
                }
                else
                {
                    Flags |= KERB_KDC_REQUEST_BODY_FLAGS.ServerName;

                    var server_parts = service.Split('/');
                    var server_type = KERB_PRINCIPAL_NAME_TYPE.NT_SRV_INST;

                    if (server_parts.Length < 2)
                    {
                        if (service.Contains("@"))
                            server_type = KERB_PRINCIPAL_NAME_TYPE.NT_ENTERPRISE;
                        else
                            server_type = KERB_PRINCIPAL_NAME_TYPE.NT_PRINCIPAL;
                    }

                    ServerName = new KERB_PRINCIPAL_NAME(server_type, server_parts);
                }

                if (start_time == null)
                    StartTime = default;
                else
                {
                    Flags |= KERB_KDC_REQUEST_BODY_FLAGS.StartTime;
                    StartTime = new KERB_TIME(start_time.Value);
                }

                EndTime = new KERB_TIME(end_time);

                if (renew_until == null)
                    RenewUntil = default;
                else
                {
                    Flags |= KERB_KDC_REQUEST_BODY_FLAGS.RenewUntil;
                    RenewUntil = new KERB_TIME(renew_until.Value);
                }

                Nonce = new Random().Next(1, int.MaxValue);

                if (encryption_types == null)
                    throw new ArgumentException("KERB_KDC_REQUEST_BODY must specify encryption types");
                else
                    EncryptionType = new LinkedList<KERB_ETYPE_WRAPPER>(encryption_types.Select(t => new KERB_ETYPE_WRAPPER(t)));

                if (addresses == null)
                    Addresses = default;
                else
                {
                    Flags |= KERB_KDC_REQUEST_BODY_FLAGS.Addresses;
                    Addresses = new LinkedList<KERB_HOST_ADDRESS_ENTRY>(addresses);
                }

                if (enc_authorization_data == null)
                    EncAuthorizationData = default;
                else
                {
                    Flags |= KERB_KDC_REQUEST_BODY_FLAGS.EncAuthorizationData;
                    EncAuthorizationData = enc_authorization_data.Value;
                }

                if (additional_tickets == null)
                    AdditionalTickets = default;
                else
                {
                    Flags |= KERB_KDC_REQUEST_BODY_FLAGS.AdditionalTickets;
                    AdditionalTickets = new LinkedList<KERB_TICKET>(additional_tickets);
                }
            }

            public void Dispose()
            {
                KdcOptions.Dispose();
                ClientName.Dispose();
                ServerName.Dispose();
                EncryptionType.Dispose();
                Addresses.Dispose();
                EncAuthorizationData.Dispose();
                AdditionalTickets.Dispose();
            }
        };

        [Flags]
        public enum KERB_KDC_REQUEST_FLAGS : ushort
        {
            None = 0,
            PreauthData = 0x80,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_KDC_REQUEST : IDisposable // KERB_AS_REQUEST, KERB_TGS_REQUEST
        {
            public KERB_KDC_REQUEST_FLAGS Flags;
            public int Version;
            public KERB_MESSAGE_TYPE MessageType;
            public LinkedList<KERB_PA_DATA> PreauthData;
            public KERB_KDC_REQUEST_BODY RequestBody;

            public KERB_KDC_REQUEST(KERB_MESSAGE_TYPE message_type, IEnumerable<KERB_PA_DATA> preauth_data, KERB_KDC_OPTIONS kdc_options, 
                string username, string domain, string service, DateTime? start_time, DateTime end_time, DateTime? renew_until, 
                IEnumerable<KERB_ETYPE> encryption_types, IEnumerable<KERB_HOST_ADDRESS_ENTRY> addresses, 
                KERB_ENCRYPTED_DATA? enc_authorization_data, IEnumerable<KERB_TICKET> additional_tickets)
            {
                Flags = KERB_KDC_REQUEST_FLAGS.None;
                Version = 5;
                MessageType = message_type;

                if (preauth_data == null)
                    PreauthData = default;
                else
                {
                    Flags |= KERB_KDC_REQUEST_FLAGS.PreauthData;
                    PreauthData = new LinkedList<KERB_PA_DATA>(preauth_data);
                }

                RequestBody = new KERB_KDC_REQUEST_BODY(kdc_options, username, domain, service, start_time, end_time,
                    renew_until, encryption_types, addresses, enc_authorization_data, additional_tickets);
            }

            public void Dispose()
            {
                PreauthData.Dispose();
                RequestBody.Dispose();
            }
        }

        [Flags]
        public enum KERB_ENCRYPTED_KDC_REPLY_FLAGS : ushort
        {
            KeyExpiration = 0x80,
            StartTime = 0x40,
            RenewUntil = 0x20,
            ClientAddresses = 0x10,
            EncryptedPaData = 0x08
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ENCRYPTED_KDC_REPLY
        {
            public KERB_ENCRYPTED_KDC_REPLY_FLAGS Flags;
            public KERB_ENCRYPTION_KEY SessionKey;
            public LinkedList<KERB_LAST_REQUEST> LastRequest;
            public int Nonce;
            public KERB_TIME KeyExpiration;
            public BIT_STRING TicketFlags;
            public KERB_TIME AuthTime;
            public KERB_TIME StartTime;
            public KERB_TIME EndTime;
            public KERB_TIME RenewUntil;
            [MarshalAs(UnmanagedType.LPStr)] public string ServerRealm;
            public KERB_PRINCIPAL_NAME ServerName;
            public LinkedList<KERB_HOST_ADDRESS_ENTRY> ClientAddresses;
            public LinkedList<KERB_PA_DATA> EncryptedPreauthData;
        }

        [Flags]
        public enum KERB_KDC_REPLY_FLAGS : ushort
        {
            PreauthData = 0x80,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_KDC_REPLY // KERB_AS_REPLY, KERB_TGS_REPLY
        {
            public KERB_KDC_REPLY_FLAGS Flags;
            public int Version;
            public KERB_MESSAGE_TYPE MessageType;
            public LinkedList<KERB_PA_DATA> PreauthData;
            [MarshalAs(UnmanagedType.LPStr)] public string ClientRealm;
            public KERB_PRINCIPAL_NAME ClientName;
            public KERB_TICKET Ticket;
            public KERB_ENCRYPTED_DATA EncryptedPart;
        }

        [Flags]
        public enum ETYPE_INFO2_ENTRY_FLAGS : ushort
        {
            Salt = 0x80,
            S2kParams = 0x40,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ETYPE_INFO2_ENTRY
        {
            public ETYPE_INFO2_ENTRY_FLAGS Flags;
            public KERB_ETYPE EncryptionType;
            [MarshalAs(UnmanagedType.LPStr)] public string Salt;
            public OCTET_STRING S2kParams;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ETYPE_INFO2_LIST
        {
            public LinkedList<ETYPE_INFO2_ENTRY> List;
        }

        [Flags]
        public enum KERB_ERROR_FLAGS : ushort
        {
            ClientTime = 0x80,
            ClientUsec = 0x40,
            ClientRealm = 0x20,
            ClientName = 0x10,
            ErrorText = 0x08,
            ErrorData = 0x04
        }

        public enum KERB_ERROR_CODE : uint
        {
            KDC_ERR_NONE = 0,                           // No error
            KDC_ERR_NAME_EXP = 1,                       // Client's entry in database has expired
            KDC_ERR_SERVICE_EXP = 2,                    // Server's entry in database has expired
            KDC_ERR_BAD_PVNO = 3,                       // Requested protocol version number not supported
            KDC_ERR_C_OLD_MAST_KVNO = 4,                // Client's key encrypted in old master key
            KDC_ERR_S_OLD_MAST_KVNO = 5,                // Server's key encrypted in old master key
            KDC_ERR_C_PRINCIPAL_UNKNOWN = 6,            // Client not found in Kerberos database
            KDC_ERR_S_PRINCIPAL_UNKNOWN = 7,            // Server not found in Kerberos database
            KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8,           // Multiple principal entries in database
            KDC_ERR_NULL_KEY = 9,                       // The client or server has a null key
            KDC_ERR_CANNOT_POSTDATE = 10,               // Ticket not eligible for postdating
            KDC_ERR_NEVER_VALID = 11,                   // Requested starttime is later than end time
            KDC_ERR_POLICY = 12,                        // KDC policy rejects request
            KDC_ERR_BADOPTION = 13,                     // KDC cannot accommodate requested option
            KDC_ERR_ETYPE_NOSUPP = 14,                  // KDC has no support for encryption type
            KDC_ERR_SUMTYPE_NOSUPP = 15,                // KDC has no support for checksum type
            KDC_ERR_PADATA_TYPE_NOSUPP = 16,            // KDC has no support for padata type
            KDC_ERR_TRTYPE_NOSUPP = 17,                 // KDC has no support for transited type
            KDC_ERR_CLIENT_REVOKED = 18,                // Clients credentials have been revoked
            KDC_ERR_SERVICE_REVOKED = 19,               // Credentials for server have been revoked
            KDC_ERR_TGT_REVOKED = 20,                   // TGT has been revoked
            KDC_ERR_CLIENT_NOTYET = 21,                 // Client not yet valid; try again later
            KDC_ERR_SERVICE_NOTYET = 22,                // Server not yet valid; try again later
            KDC_ERR_KEY_EXPIRED = 23,                   // Password has expired; change password to reset
            KDC_ERR_PREAUTH_FAILED = 24,                // Pre-authentication information was invalid
            KDC_ERR_PREAUTH_REQUIRED = 25,              // Additional pre-authentication required
            KDC_ERR_SERVER_NOMATCH = 26,                // Requested server and ticket don't match
            KDC_ERR_MUST_USE_USER2USER = 27,            // Server principal valid for user2user only
            KDC_ERR_PATH_NOT_ACCEPTED = 28,             // KDC Policy rejects transited path
            KDC_ERR_SVC_UNAVAILABLE = 29,               // A service is not available
            KRB_AP_ERR_BAD_INTEGRITY = 31,              // Integrity check on decrypted field failed
            KRB_AP_ERR_TKT_EXPIRED = 32,                // Ticket expired
            KRB_AP_ERR_TKT_NYV = 33,                    // Ticket not yet valid
            KRB_AP_ERR_REPEAT = 34,                     // Request is a replay
            KRB_AP_ERR_NOT_US = 35,                     // The ticket isn't for us
            KRB_AP_ERR_BADMATCH = 36,                   // Ticket and authenticator don't match
            KRB_AP_ERR_SKEW = 37,                       // Clock skew too great
            KRB_AP_ERR_BADADDR = 38,                    // Incorrect net address
            KRB_AP_ERR_BADVERSION = 39,                 // Protocol version mismatch
            KRB_AP_ERR_MSG_TYPE = 40,                   // Invalid msg type
            KRB_AP_ERR_MODIFIED = 41,                   // Message stream modified
            KRB_AP_ERR_BADORDER = 42,                   // Message out of order
            KRB_AP_ERR_BADKEYVER = 44,                  // Specified version of key is not available
            KRB_AP_ERR_NOKEY = 45,                      // Service key not available
            KRB_AP_ERR_MUT_FAIL = 46,                   // Mutual authentication failed
            KRB_AP_ERR_BADDIRECTION = 47,               // Incorrect message direction
            KRB_AP_ERR_METHOD = 48,                     // Alternative authentication method required
            KRB_AP_ERR_BADSEQ = 49,                     // Incorrect sequence number in message
            KRB_AP_ERR_INAPP_CKSUM = 50,                // Inappropriate type of checksum in message
            KRB_AP_PATH_NOT_ACCEPTED = 51,              // Policy rejects transited path
            KRB_ERR_RESPONSE_TOO_BIG = 52,              // Response too big for UDP; retry with TCP
            KRB_ERR_GENERIC = 60,                       // Generic error (description in e-text)
            KRB_ERR_FIELD_TOOLONG = 61,                 // Field is too long for this implementation
            KDC_ERROR_CLIENT_NOT_TRUSTED = 62,          // Reserved for PKINIT
            KDC_ERROR_KDC_NOT_TRUSTED = 63,             // Reserved for PKINIT
            KDC_ERROR_INVALID_SIG = 64,                 // Reserved for PKINIT
            KDC_ERR_KEY_TOO_WEAK = 65,                  // Reserved for PKINIT
            KDC_ERR_CERTIFICATE_MISMATCH = 66,          // Reserved for PKINIT
            KRB_AP_ERR_NO_TGT = 67,                     // No TGT available to validate USER-TO-USER
            KDC_ERR_WRONG_REALM = 68,                   // Reserved for future use
            KRB_AP_ERR_USER_TO_USER_REQUIRED = 69,      // Ticket must be for USER-TO-USER
            KDC_ERR_CANT_VERIFY_CERTIFICATE = 70,       // Reserved for PKINIT
            KDC_ERR_INVALID_CERTIFICATE = 71,           // Reserved for PKINIT
            KDC_ERR_REVOKED_CERTIFICATE = 72,           // Reserved for PKINIT
            KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73,     // Reserved for PKINIT
            KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74, // Reserved for PKINIT
            KDC_ERR_CLIENT_NAME_MISMATCH = 75,          // Reserved for PKINIT
            KDC_ERR_KDC_NAME_MISMATCH = 76,             // Reserved for PKINIT
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ERROR
        {
            public KERB_ERROR_FLAGS Flags;
            public int Version;
            public KERB_MESSAGE_TYPE MessageType;
            public KERB_TIME ClientTime;
            public int ClientUsec;
            public KERB_TIME ServerTime;
            public int ServerUsec;
            public KERB_ERROR_CODE ErrorCode;
            [MarshalAs(UnmanagedType.LPStr)] public string ClientRealm;
            public KERB_PRINCIPAL_NAME ClientName;
            [MarshalAs(UnmanagedType.LPStr)] public string Realm;
            public KERB_PRINCIPAL_NAME ServerName;
            public CHAR_STRING ErrorText;
            public OCTET_STRING ErrorData;

            public override string ToString()
            {
                if (Flags.HasFlag(KERB_ERROR_FLAGS.ErrorText))
                    return $"Kerberos failed with error code '{ErrorCode}': {ErrorText}";
                else
                    return $"Kerberos failed with error code '{ErrorCode}'";
            }

            public string GetEtypeInfo2Salt()
            {
                if (ErrorCode == KERB_ERROR_CODE.KDC_ERR_PREAUTH_FAILED && Flags.HasFlag(KERB_ERROR_FLAGS.ErrorData))
                {
                    using (var PreauthDataListWrapper = Interop.DecodeObject<KERB_PREAUTH_DATA_LIST>(ErrorData.ToBytes(), KERB_ASN1_PDU.KerbPreauthDataList))
                    {
                        foreach (var PreauthData in PreauthDataListWrapper.Object.List.ParseList())
                        {
                            if (PreauthData.PreauthDataType == KERB_PA_DATA_TYPE.PA_ETYPE_INFO2)
                            {
                                using (var EtypeInfo2Wrapper = Interop.DecodeObject<ETYPE_INFO2_LIST>(PreauthData.PreauthData.ToBytes(), KERB_ASN1_PDU.KerbEtypeInfo2))
                                {
                                    foreach (var EtypeInfo2 in EtypeInfo2Wrapper.Object.List.ParseList())
                                    {
                                        if (EtypeInfo2.Flags.HasFlag(ETYPE_INFO2_ENTRY_FLAGS.Salt))
                                            return EtypeInfo2.Salt;
                                    }
                                }
                            }
                        }
                    }
                }

                return null;
            }
        };

        public class KerbSaltException : Exception
        {
            public string Salt { get; set; }

            public KerbSaltException(string salt) 
                : base(string.Empty)
            {
                Salt = salt;
            }
        }
    }
}
