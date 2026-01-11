#pragma once
/**
 * RegistrySecurity.h - Secure registry access control
 *
 * Provides utilities to set proper ACLs on credential provider registry keys
 * to prevent unauthorized modification of security-critical settings.
 */

#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

class RegistrySecurity {
public:
    /**
     * Set registry key ACL to allow only Administrators and SYSTEM full access
     * This should be called during installation for sensitive keys like:
     * - worldposta_integration_key_enc
     * - worldposta_secret_key_enc
     * - excluded_account
     *
     * @param hKey Registry root key
     * @param subKey Path to the key to secure
     * @return true on success, false on failure
     */
    static bool SecureRegistryKey(HKEY hKey, LPCWSTR subKey);

    /**
     * Check if registry key has secure ACL (admin-only write access)
     * @param hKey Registry root key
     * @param subKey Path to the key
     * @return true if properly secured, false otherwise
     */
    static bool IsRegistryKeySecure(HKEY hKey, LPCWSTR subKey);

    /**
     * Initialize security for all WorldPosta credential provider registry keys
     * Call this during installation or first run
     * @return true if all keys secured successfully
     */
    static bool InitializeSecureRegistry();
};
