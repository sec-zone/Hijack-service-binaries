# Hijack-service-binaries

A PowerShell security auditing tool that identifies Windows service binaries that can be modified by the current user—a potential privilege escalation vector.

## Overview

This script scans all Windows services (except system32 and svchost) and checks if the current user has write, modify, or full control permissions on the service executable files. If dangerous permissions are detected, it alerts the user with detailed information about the vulnerable service.

## Features

- 🔍 Scans all non-system Windows services
- 🛡️ Checks file ACLs (Access Control Lists) for dangerous permissions
- ⚠️ Identifies privilege escalation opportunities
- 📋 Displays service name, account, path, and permission details
- 🎯 Filters out system services automatically

## How It Works

1. Retrieves the current user's identity and security principal
2. Enumerates all Win32 services via CIM (Common Information Model)
3. Filters out services in system32 and svchost
4. For each service binary, retrieves the ACL (Access Control List)
5. Checks if the current user has Write, Modify, or FullControl rights
6. Reports any services where the current user can modify the binary

## Usage

```powershell
powershell.exe .\hsb.ps1
```

You can run it with low privilege user.

## Output

When a vulnerable service is found:
```
⚠️ Current user CAN modify service binary!
Service: ServiceName
Runs As: ACCOUNT
Path: C:\Path\To\Service.exe
Matched Identity: DOMAIN\USER
Rights: Write, Modify, FullControl
```

## Security Impact

If a service binary can be modified by a non-administrative user:
1. The attacker can replace the binary with a malicious version
2. When the service is restarted, the malicious binary runs with the service's privileges
3. This can lead to privilege escalation if the service runs as SYSTEM or another high-privilege account

## Disclaimer

This tool is intended for authorized security assessments and system administration tasks only. Unauthorized access to computer systems is illegal.
