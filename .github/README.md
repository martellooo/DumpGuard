# DumpGuard
[![BSD3 License](https://img.shields.io/badge/License-BSD%203--Clause-orange.svg?style=flat)](../LICENSE)
[![Slack](https://img.shields.io/badge/Slack-SpecterOps-02B36C)](https://slack.specterops.io)
[![Sponsored by SpecterOps](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/specterops/.github/main/config/shield.json)](https://github.com/specterops)

![Logo](logo.jpeg)

DumpGuard is a credential dumping tool that can extract the NTLMv1 hashes of users on modern Windows systems.

The tool relies on the _Remote Credential Guard_ protocol, and allows credential dumping even when _Credential Guard_ is enabled on the local host. You may download prebuilt copies from the release section of this repository.

**Disclaimer:** This tool is provided strictly for educational and legitimate testing purposes only. The author of this repository does not condone or support any type of misuse and assumes no responsibility for damages or legal consequences incurred as a result of using this tool.

## Usage Overview

The following table depicts the different techniques supported by the program as well as their requirements and their ability to dump credentials protected by Credential Guard.

| Technique | Requires<br>SYSTEM | Requires<br>SPN Account | Can Dump<br>Credential Guard |
| -------- | :-------: | :-------: | :-------: |
| Extract own credentials via Remote Credential Guard protocol | :x:| ✅ | ✅ |
| Extract all credentials via Remote Credential Guard protocol | ✅ | ✅ | ✅ |
| Extract all credentials via Microsoft v1 authentication package | ✅ | :x: | :x: |

## Dumping Own Session (using Remote Credential Guard)
To dump an NTLMv1 response for the current user from an unprivileged context, we can authenticate towards an SPN-enabled account using Remote Credential Guard, and leverage the established security context to request an NTLMv1 hash from the NtlmCredIsoRemote interface.

This works regardless of the state of Credential Guard, but requires credentials for an SPN-enabled account.

Privilege Requirement: **None**.

```
DumpGuard.exe /mode:self /domain:<DOMAIN> /username:<SAMACCOUNTNAME> /password:<PASSWORD> [/spn:<SPN>]
```

## Dumping All Sessions (using Remote Credential Guard)
To dump NTLMv1 responses for all currently authenticated users from a privileged SYSTEM context, we can impersonate tokens from running processes, then authenticate towards an SPN-enabled account using Remote Credential Guard, and leverage the established security context to request an NTLMv1 hash from the NtlmCredIsoRemote interface.

This works regardless of the state of Credential Guard, but requires credentials for an SPN-enabled account.

Privilege Requirement: **SYSTEM**.

```
DumpGuard.exe /mode:all /domain:<DOMAIN> /username:<SAMACCOUNTNAME> /password:<PASSWORD> [/spn:<SPN>]
```

## Dumping All Sessions (using Microsoft v1 authentication package)
To dump NTLMv1 responses for all currently authenticated users from a privileged SYSTEM context, we can interact with the NTLM SSP and request responses for each individual logon session ID.

This works only under the following conditions:
- Credential Guard is disabled on the local system (we can extract from all local sessions).
- Remote users are authenticated to the local system from a remote host over Remote Credential Guard.

Privilege Requirement: **SYSTEM**.

```
DumpGuard.exe /mode:all
```

This is equivalent to the following [LSA Whisperer](https://github.com/EvanMcBroom/lsa-whisperer) command:
```
lsa-whisperer.exe msv1_0 Lm20GetChallengeResponse --luid {session id} --challenge {challenge to clients} [flags...]
```

## Bonus Information

I have reverse engineered and recreated all the interfaces exposed by Credential Guard (*LsaIso.exe*) and included them in this repository, in case anyone wants to conduct further research.

## Acknowledgements

Thank you to [SpecterOps](https://specterops.io/) for supporting this research and to my coworkers who have helped with its development.
- [Elad Shamir](https://twitter.com/elad_shamir) - for inspiring this tool and research, and for offering valuable perspective and encouragement whenever I hit a wall.
- [Evan McBroom](https://github.com/EvanMcBroom) - for sharing useful insights on LSA internals and providing ASN.1 encoders for most of the structures used in this project.

## Related Tools
- [LSA Whisperer](https://github.com/EvanMcBroom/lsa-whisperer) ([Evan McBroom](https://github.com/EvanMcBroom)) - A toolset for interacting with authentication packages.
- [Rubeus](https://github.com/GhostPack/Rubeus) ([Will Schroeder](https://github.com/HarmJ0y), [Charlie Clark](https://x.com/exploitph)) - A C# toolset for raw Kerberos interaction and abuses.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) ([Benjamin Delpy](https://github.com/gentilkiwi)) - A little tool to play with Windows security.
- [Kekeo](https://github.com/gentilkiwi/kekeo) ([Benjamin Delpy](https://github.com/gentilkiwi)) - A little toolbox to play with Microsoft Kerberos in C.

## Related Work
- [Oliver Lyak](https://github.com/ly4k) ([2022](https://research.ifcr.dk/pass-the-challenge-defeating-windows-defender-credential-guard-31a892eee22)) - For what is, to my knowledge, the only public research on dumping credentials protected by Credential Guard.
- [James Forshaw](https://x.com/tiraniddo) ([2022](https://project-zero.issues.chromium.org/issues/42451433), [2022](https://project-zero.issues.chromium.org/issues/42451435), [2022](https://project-zero.issues.chromium.org/issues/42451397), [2022](https://project-zero.issues.chromium.org/issues/42451436)) - For vulnerability submissions that slightly documents some of the undocumented interfaces that we have researched.
