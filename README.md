# WorldPosta Windows Credential Provider

Two-Factor Authentication for Windows RDP and local login using WorldPosta Authenticator.

## Overview

This Windows Credential Provider integrates WorldPosta Authenticator with Windows login, allowing users to authenticate using:
- **TOTP codes** from the WorldPosta Authenticator app
- **Push notifications** for approve/deny authentication

## Supported Windows Versions

- Windows 10/11 (64-bit)
- Windows Server 2016/2019/2022

## Installation

### GUI Installation

1. Download `WorldPostaAuthenticator.msi` from Releases
2. Run the installer
3. Enter your API credentials from WorldPosta Admin Portal:
   - **Integration Key**
   - **Secret Key**
4. Choose authentication options
5. Complete installation and restart

### Silent Installation

```batch
msiexec /i WorldPostaAuthenticator.msi /quiet ^
  WORLDPOSTA_INTEGRATION_KEY=int_your_key ^
  WORLDPOSTA_SECRET_KEY=sk_your_secret ^
  ENABLE_RDP=1 ^
  ENABLE_LOCAL=0
```

## Configuration

Registry path: `HKEY_CLASSES_ROOT\CLSID\{11A4894C-0968-40D0-840E-FAA4B8984916}`

| Value | Type | Description |
|-------|------|-------------|
| `worldposta_api_endpoint` | REG_SZ | API URL (default: https://api.worldposta.com) |
| `worldposta_integration_key` | REG_SZ | Your integration key |
| `worldposta_secret_key` | REG_SZ | Your secret key |
| `cpus_logon` | REG_DWORD | 0=all, 1=RDP only, 2=local only |

## Building from Source

### Requirements
- Windows 10/11
- Visual Studio 2019/2022
- WiX Toolset v3.11+

### Build
```batch
msbuild multiOTPCredentialProvider.sln /p:Configuration=Release /p:Platform=x64
```

### GitHub Actions
Push to `main` branch triggers automatic build and installer creation.

## License

Apache License 2.0

Based on [multiOTPCredentialProvider](https://github.com/multiOTP/multiOTPCredentialProvider).
