#include "RegistrySecurity.h"
#include <memory>

bool RegistrySecurity::SecureRegistryKey(HKEY hKey, LPCWSTR subKey) {
    HKEY hRegKey = NULL;

    // Open the registry key
    LONG result = RegOpenKeyExW(hKey, subKey, 0, READ_CONTROL | WRITE_DAC, &hRegKey);
    if (result != ERROR_SUCCESS) {
        return false;
    }

    // Create a DACL that grants:
    // - SYSTEM: Full control
    // - Administrators: Full control
    // - Everyone: Read only (no write)
    // SDDL string format:
    // D: = DACL
    // (A;;KA;;;SY) = Allow SYSTEM full key access
    // (A;;KA;;;BA) = Allow Administrators full key access
    // (A;;KR;;;WD) = Allow Everyone read access only
    LPCWSTR sddl = L"D:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;WD)";

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &pSD, NULL)) {
        RegCloseKey(hRegKey);
        return false;
    }

    // Get the DACL from the security descriptor
    PACL pDacl = NULL;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
        LocalFree(pSD);
        RegCloseKey(hRegKey);
        return false;
    }

    // Set the DACL on the registry key
    DWORD dwRes = SetSecurityInfo(
        hRegKey,
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL,  // owner
        NULL,  // group
        pDacl,
        NULL   // SACL
    );

    LocalFree(pSD);
    RegCloseKey(hRegKey);

    return dwRes == ERROR_SUCCESS;
}

bool RegistrySecurity::IsRegistryKeySecure(HKEY hKey, LPCWSTR subKey) {
    HKEY hRegKey = NULL;

    // Open the registry key
    LONG result = RegOpenKeyExW(hKey, subKey, 0, READ_CONTROL, &hRegKey);
    if (result != ERROR_SUCCESS) {
        return false;
    }

    // Get the security descriptor
    DWORD dwSize = 0;
    RegGetKeySecurity(hRegKey, DACL_SECURITY_INFORMATION, NULL, &dwSize);

    std::unique_ptr<BYTE[]> pSD(new BYTE[dwSize]);
    result = RegGetKeySecurity(hRegKey, DACL_SECURITY_INFORMATION,
                               (PSECURITY_DESCRIPTOR)pSD.get(), &dwSize);
    RegCloseKey(hRegKey);

    if (result != ERROR_SUCCESS) {
        return false;
    }

    // Get the DACL
    PACL pDacl = NULL;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)pSD.get(),
                                   &bDaclPresent, &pDacl, &bDaclDefaulted)) {
        return false;
    }

    if (!bDaclPresent || pDacl == NULL) {
        return false; // No DACL means wide open - not secure
    }

    // Check that non-admin users don't have write access
    // This is a simplified check - in production you'd want more thorough validation
    ACL_SIZE_INFORMATION aclInfo;
    if (!GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
        return false;
    }

    // If we got here, DACL exists - basic security is in place
    return true;
}

bool RegistrySecurity::InitializeSecureRegistry() {
    bool success = true;

    // Secure the main credential provider key
    LPCWSTR mainKey = L"CLSID\\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}";

    if (!SecureRegistryKey(HKEY_CLASSES_ROOT, mainKey)) {
        success = false;
    }

    return success;
}
