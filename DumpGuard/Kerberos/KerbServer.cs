using DumpGuard.Kerberos.Networking;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;
using static DumpGuard.Kerberos.KerbBaseTypes;
using static DumpGuard.Kerberos.KerbCrypto;
using static DumpGuard.Kerberos.KerbGssTypes;

namespace DumpGuard.Kerberos
{
    public enum KERB_SERVER_STATE
    {
        None = 0,
        TgtRequestSent = 1,
        TgtReplySent = 2,
        ApRequestSent = 3,
        ApReplySent = 4,
        Authenticated = 5,
        ErrorMessageSent = 6,
        InvalidState = 7,
    }

    internal class KerbServer
    {
        private string Realm { get; set; }
        private string Username { get; set; }
        private string Password { get; set; }

        private Tuple<KERB_ETYPE, byte[]> SessionKey { get; set; } = null;

        private Tuple<KERB_ETYPE, byte[]> InitiatorSubKey { get; set; } = null;
        private Tuple<KERB_ETYPE, byte[]> AcceptorSubkey { get; set; } = new Tuple<KERB_ETYPE, byte[]>(KERB_ETYPE.aes256, new byte[]
        {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
            0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
        });

        public ulong InitiatorSequenceNumber { get; set; } = 0;
        public ulong AcceptorSequenceNumber { get; set; } = 0x12345678;

        private Dictionary<KERB_ETYPE, byte[]> LongTermKeys { get; set; } = new Dictionary<KERB_ETYPE, byte[]>();

        public KERB_SERVER_STATE ServerState { get; set; } = KERB_SERVER_STATE.None;

        public KerbServer(string domain, string username, string password, string salt)
        {
            Realm = domain;
            Username = username;
            Password = password;

            BuildKeyList(salt);
        }

        private void BuildKeyList(string salt)
        {
            if (string.IsNullOrEmpty(salt))
            {
                if (Username.EndsWith("$"))
                    salt = $"{Realm.ToUpperInvariant()}host{Username.TrimEnd('$').ToLowerInvariant()}.{Realm.ToLowerInvariant()}";
                else
                    salt = $"{Realm.ToUpperInvariant()}{Username.ToLowerInvariant()}";
            }

            var key_types = new KERB_ETYPE[]
            {
                KERB_ETYPE.rc4_hmac,
                KERB_ETYPE.aes128,
                KERB_ETYPE.aes256,
            };

            foreach (var key_type in key_types)
                LongTermKeys[key_type] = KerbHashPassword(key_type, Password, salt);
        }

        public byte[] AcceptKerberosToken(byte[] Request)
        {
            if (Request[0] == 0x60) // GSS-API pseudo ASN.1 frame
            {
                using (var KerbRequestWrapper = Interop.DecodeObject<InitialContextToken>(Request, GSSAPI_ASN1_PDU.InitialContextToken))
                    return HandleTokenProcessing(KerbRequestWrapper.Object.TokenId, KerbRequestWrapper.Object.InnerToken.ToBytes(), true);
            }
            else
            {
                return HandleTokenProcessing((KERB_GSS_TOKEN_ID)BitConverter.ToUInt16(Request.Take(2).ToArray(), 0), Request.Skip(2).ToArray(), false);
            }
        }

        private byte[] HandleTokenProcessing(KERB_GSS_TOKEN_ID TokenId, byte[] Token, bool UseGssApi)
        {
            switch (TokenId)
            {
                case KERB_GSS_TOKEN_ID.KerbTgtReq:
                    return HandleTgtRequest(Token, UseGssApi);

                case KERB_GSS_TOKEN_ID.KerbApReq:
                    return HandleApRequest(Token, UseGssApi);

                default:
                    throw new NotSupportedException($"Kerberos handling for Token ID '{TokenId}' is not currently supported");
            }
        }

        private byte[] HandleTgtRequest(byte[] Request, bool UseGssApi)
        {
            using (var TgtRequestWrapper = Interop.DecodeObject<KERB_TGT_REQUEST>(Request, KERB_ASN1_PDU.KerbTgtRequest))
            {
                if (TgtRequestWrapper.Object.Version != 5)
                    throw new InvalidOperationException("TGT-REQ version must be 5");
                else if (TgtRequestWrapper.Object.MessageType != KERB_MESSAGE_TYPE.KrbTgtReqU2U)
                    throw new NotSupportedException($"Kerberos handling for TGT-REQ with MessageType '{TgtRequestWrapper.Object.MessageType}' is not currently supported");

                var TgtRequest = TgtRequestWrapper.Object;

                byte[] as_rep = null;

                try
                {
                    as_rep = KerbNetworking.SendKdcRequest(BuildAsReq(LongTermKeys[KERB_ETYPE.aes256], KERB_ETYPE.aes256, Username, Realm, null));
                }
                catch (KerbSaltException e)
                {
                    BuildKeyList(e.Salt);
                    as_rep = KerbNetworking.SendKdcRequest(BuildAsReq(LongTermKeys[KERB_ETYPE.aes256], KERB_ETYPE.aes256, Username, Realm, null));
                }

                using (var AsReplyWrapper = Interop.DecodeObject<KERB_KDC_REPLY>(as_rep, KERB_ASN1_PDU.KerbAsReply))
                {
                    var encrypted_part = AsReplyWrapper.Object.EncryptedPart.Decrypt(KERB_KEY_USAGE.AsRepEncryptedPart, LongTermKeys);

                    using (var DecryptedAsReplyWrapper = Interop.DecodeObject<KERB_ENCRYPTED_KDC_REPLY>(encrypted_part, KERB_ASN1_PDU.KerbEncryptedAsReply))
                    {
                        SessionKey = new Tuple<KERB_ETYPE, byte[]>(
                            DecryptedAsReplyWrapper.Object.SessionKey.KeyType,
                            DecryptedAsReplyWrapper.Object.SessionKey.KeyValue.ToBytes());
                    }

                    using (var tgt_rep = new KERB_TGT_REPLY(KERB_MESSAGE_TYPE.KrbTgtRepU2U, AsReplyWrapper.Object.Ticket))
                    {
                        var response = Interop.EncodeObject(tgt_rep, KERB_ASN1_PDU.KerbTgtReply);

                        if (UseGssApi)
                        {
                            using (var gss_api_token = new InitialContextToken("1.2.840.113554.1.2.2.3", KERB_GSS_TOKEN_ID.KerbExportedNameToken, response))
                                response = Interop.EncodeObject(gss_api_token, GSSAPI_ASN1_PDU.InitialContextToken);
                        }

                        ServerState = KERB_SERVER_STATE.TgtReplySent;
                        return response;
                    }
                }
            }
        }

        private byte[] BuildAsReq(byte[] key, KERB_ETYPE etype, string username, string domain, string service)
        {
            var pa_data = new List<KERB_PA_DATA>
            {
                new KERB_PA_DATA(KERB_PA_DATA_TYPE.PA_ENC_TIMESTAMP, BuildEncryptedTimestamp(key, etype, DateTime.UtcNow)),
                new KERB_PA_DATA(KERB_PA_DATA_TYPE.PA_PAC_REQUEST, BuildPacRequest(true))
            };

            using (var request = new KERB_KDC_REQUEST(KERB_MESSAGE_TYPE.KrbAsReq, pa_data, KERB_KDC_OPTIONS.Forwardable | KERB_KDC_OPTIONS.Renewable | KERB_KDC_OPTIONS.RenewableOk,
                username, domain, service, null, DateTime.UtcNow.AddYears(1), DateTime.UtcNow.AddYears(1), new KERB_ETYPE[] { KERB_ETYPE.aes256 }, null, null, null))
            {
                return Interop.EncodeObject(request, KERB_ASN1_PDU.KerbAsRequest);
            }
        }

        private byte[] BuildEncryptedTimestamp(byte[] key, KERB_ETYPE etype, DateTime timestamp_utc)
        {
            var bytes = KerbEncryptData(etype, KERB_KEY_USAGE.AsReqPaEncTimestamp, key, BuildTimestamp(timestamp_utc));
            return Interop.EncodeObject(new KERB_ENCRYPTED_DATA(etype, bytes), KERB_ASN1_PDU.KerbEncryptedData);
        }

        private byte[] BuildTimestamp(DateTime timestamp_utc)
        {
            return Interop.EncodeObject(new KERB_ENCRYPTED_TIMESTAMP(timestamp_utc), KERB_ASN1_PDU.KerbEncryptedTimestamp);
        }

        private byte[] BuildPacRequest(bool include_pac)
        {
            return Interop.EncodeObject(new KERB_PA_PAC_REQUEST(include_pac), KERB_ASN1_PDU.KerbPaPacRequest);
        }

        private byte[] HandleApRequest(byte[] Request, bool UseGssApi)
        {
            using (var ApRequestWrapper = Interop.DecodeObject<KERB_AP_REQUEST>(Request, KERB_ASN1_PDU.KerbApRequest))
            {
                if (ApRequestWrapper.Object.Version != 5)
                    throw new InvalidOperationException("AP-REQ version must be 5");
                else if (ApRequestWrapper.Object.MessageType != KERB_MESSAGE_TYPE.KrbApReq)
                    throw new NotSupportedException($"Kerberos handling for AP-REQ with MessageType '{ApRequestWrapper.Object.MessageType}' is not currently supported");

                var ApRequest = ApRequestWrapper.Object;

                byte[] decrypted_ticket = null;

                if (((KERB_AP_REQUEST_OPTIONS)ApRequest.ApOptions.ToByte()).HasFlag(KERB_AP_REQUEST_OPTIONS.UseSessionKey))
                    decrypted_ticket = ApRequest.Ticket.EncryptedPart.Decrypt(KERB_KEY_USAGE.AsRepTgsRep, SessionKey.Item1, SessionKey.Item2);
                else
                    decrypted_ticket = ApRequest.Ticket.EncryptedPart.Decrypt(KERB_KEY_USAGE.AsRepTgsRep, LongTermKeys);

                using (var DecryptedTicketWrapper = Interop.DecodeObject<KERB_ENCRYPTED_TICKET>(decrypted_ticket, KERB_ASN1_PDU.KerbEncryptedTicket))
                {
                    var ticket_key_type = DecryptedTicketWrapper.Object.Key.KeyType;
                    var ticket_key = DecryptedTicketWrapper.Object.Key.KeyValue.ToBytes();

                    var decrypted_authenticator = ApRequest.Authenticator.Decrypt(KERB_KEY_USAGE.ApReqAuthenticator, ticket_key_type, ticket_key);

                    using (var DecryptedAuthenticatorWrapper = Interop.DecodeObject<KERB_AUTHENTICATOR>(decrypted_authenticator, KERB_ASN1_PDU.KerbAuthenticator))
                    {
                        if (DecryptedAuthenticatorWrapper.Object.Flags.HasFlag(KERB_AUTHENTICATOR_FLAGS.SubKey))
                        {
                            InitiatorSubKey = new Tuple<KERB_ETYPE, byte[]>(
                                DecryptedAuthenticatorWrapper.Object.SubKey.KeyType,
                                DecryptedAuthenticatorWrapper.Object.SubKey.KeyValue.ToBytes());
                        }

                        if (DecryptedAuthenticatorWrapper.Object.Flags.HasFlag(KERB_AUTHENTICATOR_FLAGS.SequenceNumber))
                        {
                            InitiatorSequenceNumber = Interop.SwapEndianness(BitConverter.ToUInt32(DecryptedAuthenticatorWrapper.Object.SequenceNumber.ToBytes(), 0));
                        }

                        if (!ApRequest.ApOptions.ToEnum<KERB_AP_REQUEST_OPTIONS>().HasFlag(KERB_AP_REQUEST_OPTIONS.MutualRequired))
                        {
                            ServerState = KERB_SERVER_STATE.ApRequestSent;
                            return null;
                        }
                        else
                        {
                            using (var enc_ap_reply = new KERB_ENCRYPTED_AP_REPLY(DecryptedAuthenticatorWrapper.Object.ClientTime, DecryptedAuthenticatorWrapper.Object.ClientUsec,
                                AcceptorSubkey.Item1, AcceptorSubkey.Item2, (uint)(AcceptorSequenceNumber & 0xffffffff)))
                            {
                                var encoded_enc_ap_reply = Interop.EncodeObject(enc_ap_reply, KERB_ASN1_PDU.KerbEncryptedApReply);
                                var encrypted_enc_ap_reply = KerbEncryptData(ticket_key_type, KERB_KEY_USAGE.ApRepEncryptedPart, ticket_key, encoded_enc_ap_reply);

                                using (var ap_rep = new KERB_AP_REPLY(KERB_MESSAGE_TYPE.KrbApRep, new KERB_ENCRYPTED_DATA(ticket_key_type, encrypted_enc_ap_reply)))
                                {
                                    var response = Interop.EncodeObject(ap_rep, KERB_ASN1_PDU.KerbApReply);

                                    if (UseGssApi)
                                    {
                                        using (var gss_api_token = new InitialContextToken("1.2.840.113554.1.2.2.3", KERB_GSS_TOKEN_ID.KerbApRep, response))
                                            response = Interop.EncodeObject(gss_api_token, GSSAPI_ASN1_PDU.InitialContextToken);
                                    }

                                    ServerState = KERB_SERVER_STATE.ApReplySent;
                                    return response;
                                }
                            }
                        }
                    }
                }
            }
        }

        public byte[] KerbMakeSignatureOld(byte[] data)
        {
            var key = AcceptorSubkey;

            var checksum_map = new Dictionary<KERB_ETYPE, KERB_CTYPE>()
            {
                { KERB_ETYPE.aes128, KERB_CTYPE.hmac_sha_96_aes128 },
                { KERB_ETYPE.aes256, KERB_CTYPE.hmac_sha_96_aes256 },
            };

            if (!checksum_map.ContainsKey(key.Item1))
                throw new Exception($"Attempted to make signature with unsupported key type: '{key.Item1}'");

            var token_header_managed = new MIC_TOKEN_HEADER(GSS_TOKEN_FLAGS.SentByAcceptor | GSS_TOKEN_FLAGS.AcceptorSubKey, AcceptorSequenceNumber++);
            var token_header_unmanaged = token_header_managed.ToRawBytes();

            var data_buffers = new List<byte[]>() { data, token_header_unmanaged.Take(16).ToArray() };
            var checksum = KerbChecksumData(checksum_map[key.Item1], KERB_KEY_USAGE.KgUsageAcceptorSign, key.Item2, data_buffers);

            return token_header_unmanaged.Concat(checksum).ToArray();
        }

        public byte[] KerbSealMessageOld(byte[] message)
        {
            var key = AcceptorSubkey.Item2;
            (var enc_type, var chk_type) = KerbGetEncryptionAndChecksumType(AcceptorSubkey.Item1);

            var token_signature = new KERB_GSS_SEAL_SIGNATURE(GSS_TOKEN_FLAGS.SentByAcceptor | GSS_TOKEN_FLAGS.AcceptorSubKey | GSS_TOKEN_FLAGS.Sealed, 0, 0, AcceptorSequenceNumber++);
            token_signature.Confounder = new byte[] { 0xbc, 0xc8, 0x02, 0xe5, 0x6a, 0x70, 0xe3, 0xca, 0xd7, 0x2b, 0xc5, 0x8a, 0xf9, 0x84, 0x7e, 0xb9 };
            token_signature.Checksum = KerbChecksumData(chk_type, KERB_KEY_USAGE.KgUsageAcceptorSeal, key, new List<byte[]>() { token_signature.Confounder, message, token_signature.Header.ToRawBytes() });

            (var confounder, var buffer, var header) = TransformSealBuffer(enc_type, key, KERB_KEY_USAGE.KgUsageAcceptorSeal, token_signature.Confounder, message, token_signature.Header.ToRawBytes(), true);

            token_signature.Header.RightRotationCount = Interop.SwapEndianness<ushort>(0x1c); // I dont know where 0x1c comes from

            token_signature.Confounder = confounder;
            token_signature.EncryptedHeader = header;

            return token_signature.ToRawBytes().Concat(buffer).ToArray();
        }

        public byte[] KerbUnsealMessageOld(byte[] message)
        {
            var key = AcceptorSubkey.Item2;
            (var enc_type, var chk_type) = KerbGetEncryptionAndChecksumType(AcceptorSubkey.Item1);

            var token_signature = message.Take(Marshal.SizeOf<KERB_GSS_SEAL_SIGNATURE>()).ToArray().ToStruct<KERB_GSS_SEAL_SIGNATURE>();
            var token_buffer = message.Skip(Marshal.SizeOf<KERB_GSS_SEAL_SIGNATURE>()).ToArray();

            var extra_count = Interop.SwapEndianness(token_signature.Header.ExtraCount) + 0x1c;
            var right_rotation_count = Interop.SwapEndianness(token_signature.Header.RightRotationCount) % (token_buffer.Length - 16);

            if (right_rotation_count > extra_count)
                throw new Exception("Data needs to be rotated - not currently implemented");

            (var confounder, var buffer, var header) = TransformSealBuffer(enc_type, key, KERB_KEY_USAGE.KgUsageInitiatorSeal, token_signature.Confounder, token_buffer, token_signature.EncryptedHeader, false);

            if (!token_signature.Checksum.SequenceEqual(KerbChecksumData(chk_type, KERB_KEY_USAGE.KgUsageInitiatorSeal, key, new List<byte[]>() { confounder, buffer, header })))
                throw new Exception("Failed to decrypted data as checksum was invalid");

            return buffer;
        }

        private (KERB_ETYPE, KERB_CTYPE) KerbGetEncryptionAndChecksumType(KERB_ETYPE encryption_type)
        {
            if (encryption_type == KERB_ETYPE.aes128)
                return (KERB_ETYPE.aes128_plain, KERB_CTYPE.hmac_sha_96_aes128_ki);
            else if (encryption_type == KERB_ETYPE.aes256)
                return (KERB_ETYPE.aes256_plain, KERB_CTYPE.hmac_sha_96_aes256_ki);
            else
                throw new Exception($"Attempted to perform GSS-API operation with unsupported key type: '{encryption_type}'");
        }

        private (byte[], byte[], byte[]) TransformSealBuffer(KERB_ETYPE encryption_type, byte[] key, KERB_KEY_USAGE key_usage, byte[] confounder, byte[] data, byte[] header, bool encrypt_or_decrypt)
        {
            var status = 0;

            if ((status = CDLocateCSystem(encryption_type, out IntPtr engine)) < 0)
                throw new Exception($"Could not locate crypto system for encryption type '{encryption_type}' with error: {status:x}");

            var crypto_system = Marshal.PtrToStructure<KERB_ECRYPT>(engine);

            if ((status = crypto_system.InvokeInitialize(key, key.Length, key_usage, out IntPtr crypto_context)) < 0)
                throw new Exception($"Failed to initialize crypto system with error: {status:x}");

            var crypto_buffer = confounder.Concat(data).Concat(header).ToArray();
            var crypto_trailer = crypto_buffer.Length - confounder.Length;

            if (encrypt_or_decrypt)
            {
                if ((status = crypto_system.InvokeEncryptPlain(crypto_context, crypto_trailer, 16, crypto_buffer)) < 0)
                    throw new Exception($"Failed to encrypt confounder with error: {status:x}");
            }
            else
            {
                if ((status = crypto_system.InvokeDecryptPlain(crypto_context, crypto_trailer, 16, crypto_buffer)) < 0)
                    throw new Exception($"Failed to decrypt confounder with error: {status:x}");
            }

            while (crypto_trailer > 0)
            {
                if (crypto_trailer < crypto_system.BlockSize)
                    throw new Exception($"Decryption failed as there are less than one block ({crypto_system.BlockSize} bytes) remaining");

                var offset = crypto_buffer.Length - crypto_trailer;

                if (crypto_trailer <= 2 * crypto_system.BlockSize)
                {
                    var temp = crypto_buffer.Skip(offset).ToArray();

                    if (encrypt_or_decrypt)
                    {
                        if ((status = crypto_system.InvokeEncryptPlain(crypto_context, 0, crypto_trailer, temp)) < 0)
                            throw new Exception($"Failed to encrypt sealed data tail with error: {status:x}");
                    }
                    else
                    {
                        if ((status = crypto_system.InvokeDecryptPlain(crypto_context, 0, crypto_trailer, temp)) < 0)
                            throw new Exception($"Failed to decrypt sealed data tail with error: {status:x}");
                    }

                    Array.Copy(temp, 0, crypto_buffer, offset, crypto_trailer);
                    crypto_trailer = 0;
                }
                else
                {
                    var temp = crypto_buffer.Skip(offset).Take(crypto_system.BlockSize).ToArray();

                    if (encrypt_or_decrypt)
                    {
                        if ((status = crypto_system.InvokeEncryptPlain(crypto_context, crypto_trailer, crypto_system.BlockSize, temp)) < 0)
                            throw new Exception($"Failed to encrypt sealed data with error: {status:x}");
                    }
                    else
                    {
                        if ((status = crypto_system.InvokeDecryptPlain(crypto_context, crypto_trailer, crypto_system.BlockSize, temp)) < 0)
                            throw new Exception($"Failed to decrypt sealed data with error: {status:x}");
                    }

                    Array.Copy(temp, 0, crypto_buffer, offset, crypto_system.BlockSize);
                    crypto_trailer -= crypto_system.BlockSize;
                }
            }

            var transformed_confounder = crypto_buffer.Take(16).ToArray();
            var transformed_header = crypto_buffer.Skip(crypto_buffer.Length - Marshal.SizeOf<KERB_GSS_SIGNATURE_HEADER>()).ToArray();
            var transformed_message = crypto_buffer.Skip(confounder.Length).Take(crypto_buffer.Length - transformed_confounder.Length - transformed_header.Length).ToArray();

            return (transformed_confounder, transformed_message, transformed_header);
        }
    }
}
