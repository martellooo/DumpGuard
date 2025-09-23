using DumpGuard.Kerberos;
using System;
using System.Linq;
using System.Text;
using static DumpGuard.Spnego.SpnegoBaseTypes;

namespace DumpGuard.Spnego
{
    internal class SpnegoServer
    {
        public KerbServer Kerberos { get; set; }
        private byte[] SavedMechTypeList { get; set; } = null;

        public SpnegoServer(KerbServer kerb_server)
        {
            Kerberos = kerb_server;
        }

        public bool AcceptNegotiationToken(byte[] NegoRequest, out byte[] NegoResponse)
        {
            NegoResponse = null;

            if (NegoRequest.Take(7).SequenceEqual(Encoding.ASCII.GetBytes("NTLMSSP")))
                throw new Exception("The client attempted to negotiate using NTLM");

            if (NegoRequest[0] == 0x60)
            {
                using (var InitialNegTokenWrapper = Interop.DecodeObject<InitialNegToken>(NegoRequest, SPNEGO_ASN1_PDU.InitialNegToken))
                {
                    var InitialToken = InitialNegTokenWrapper.Object.NegTokenInit;

                    if (!InitialToken.Flags.HasFlag(NegTokenInitFlags.MechToken))
                        throw new InvalidOperationException("NegTokenInit did not contain MechToken");
                    else if (InitialToken.MechTypes.ParseList()?.Any(mt => mt.ToString() == "1.2.840.113554.1.2.2") == false)
                        throw new InvalidOperationException("MechTypeList does not contain Kerberoes 5 GSS-API Mechanism (1.2.840.113554.1.2.2)");

                    SavedMechTypeList = Interop.EncodeObject(new MechTypeList(InitialToken.MechTypes), SPNEGO_ASN1_PDU.SavedMechTypeList);

                    NegoResponse = HandleTokenRequest(InitialToken.MechToken.ToBytes());
                }
            }
            else
            {
                using (var NegotiationTokenWrapper = Interop.DecodeObject<NegotiationToken>(NegoRequest, SPNEGO_ASN1_PDU.NegotiationToken))
                {
                    var ResponseToken = NegotiationTokenWrapper.Object.NegTokenTarg;

                    if (!ResponseToken.Flags.HasFlag(NegTokenTargFlags.NegResult))
                        throw new InvalidOperationException("NegTokenTarg did not contain NegResult");

                    switch (ResponseToken.NegResult)
                    {
                        case NegResult.AcceptCompleted:
                            Kerberos.ServerState = KERB_SERVER_STATE.Authenticated;
                            return true;

                        case NegResult.AcceptIncomplete:
                            NegoResponse = HandleTokenRequest(ResponseToken.ResponseToken.ToBytes());
                            break;

                        default:
                            throw new Exception($"NegTokenTarg contained unsupported NegResult: {ResponseToken.NegResult}");
                    }
                }
            }

            return false;
        }

        private byte[] HandleTokenRequest(byte[] Token)
        {
            var response_token = Kerberos.AcceptKerberosToken(Token);

            string supported_mech = null;
            byte[] mech_mic_list = null;

            if (Kerberos.ServerState == KERB_SERVER_STATE.ApReplySent || Kerberos.ServerState == KERB_SERVER_STATE.ApRequestSent)
                mech_mic_list = Kerberos.KerbMakeSignatureOld(SavedMechTypeList);
            else
                supported_mech = "1.2.840.48018.1.2.2";

            using (var response = new NegotiationToken(NegResult.AcceptIncomplete, supported_mech, response_token, mech_mic_list))
                return Interop.EncodeObject(response, SPNEGO_ASN1_PDU.NegotiationToken);
        }
    }
}
