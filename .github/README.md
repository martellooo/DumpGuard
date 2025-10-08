# DumpGuard

![Usage Scenarios](usages.png)

## Dumping Own Guarded Credentials
Privilege Requirement: **None**.

```
DumpGuard.exe /mode:self /domain:<DOMAIN> /username:<SAMACCOUNTNAME> /password:<PASSWORD>
```

## Dumping All Guarded Credentials
Privilege Requirement: **SYSTEM**.

```
DumpGuard.exe /mode:all /domain:<DOMAIN> /username:<SAMACCOUNTNAME> /password:<PASSWORD>
```

## Dumping All Non-Guarded or RCG Credential
Privilege Requirement: **SYSTEM**.

```
DumpGuard.exe /mode:all
```

## Acknowledgements

Thank you to [SpecterOps](https://specterops.io/) for supporting this research and to my coworkers who have helped with its development.
- [Elad Shamir](https://twitter.com/elad_shamir) for inspiring this tool and research, and for offering valuable perspective and encouragement whenever I hit a wall.
- [Evan McBroom](https://github.com/EvanMcBroom) for sharing useful insights on LSA internals and providing ASN.1 encoders for most of the protocols used in the project

## Related Work

- [Oliver Lyak](https://github.com/ly4k) ([2022](https://research.ifcr.dk/pass-the-challenge-defeating-windows-defender-credential-guard-31a892eee22)), for what is, to my knowledge, the only public research on dumping Credential Guard credentials
- [James Forshaw](https://x.com/tiraniddo) ([2022](https://project-zero.issues.chromium.org/issues/42451433), [2022](https://project-zero.issues.chromium.org/issues/42451435), [2022](https://project-zero.issues.chromium.org/issues/42451397), [2022](https://project-zero.issues.chromium.org/issues/42451436)), for vulnerability submissions that slightly documents some of the undocumented interfaces that we have researched
