using System;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Net.Sockets;
using static DumpGuard.Kerberos.KerbBaseTypes;

namespace DumpGuard.Kerberos.Networking
{
    internal class KerbNetworking
    {
        public static byte[] SendKdcRequest(byte[] request, string kdc = null)
        {
            kdc = kdc ?? Domain.GetCurrentDomain()?.FindDomainController(LocatorOptions.KdcRequired)?.Name;

            if (string.IsNullOrEmpty(kdc))
                throw new Exception("Could not find a domain controller");

            try
            {
                using (var client = new TcpClient(kdc, 88))
                {
                    var writer = new BinaryWriter(client.GetStream());
                    writer.Write(Interop.SwapEndianness(request.Length));
                    writer.Write(request);

                    var reader = new BinaryReader(client.GetStream());
                    var length = Interop.SwapEndianness(reader.ReadInt32());
                    var bytes = reader.ReadBytes(length);

                    if (bytes.Length != length)
                        throw new Exception($"Could only read '{bytes.Length}' of '{length}' bytes from KDC response");

                    if (Interop.ParseAsn1TagNumber(bytes[0]) == (byte)KERB_MESSAGE_TYPE.KrbError)
                    {
                        using (var KerbErrorWrapper = Interop.DecodeObject<KERB_ERROR>(bytes, KERB_ASN1_PDU.KerbError))
                        {
                            var etype_info2_salt = KerbErrorWrapper.Object.GetEtypeInfo2Salt();

                            if (!string.IsNullOrEmpty(etype_info2_salt))
                                throw new KerbSaltException(etype_info2_salt);
                            else
                                throw new Exception(KerbErrorWrapper.Object.ToString());
                        }
                    }

                    return bytes;
                }
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode == SocketError.TimedOut)
                    throw new TimeoutException($"Could not connect to KDC : {e.Message}");
                else
                    throw new Exception($"Failed to get response from KDC : {e.Message}");
            }
        }
    }
}
