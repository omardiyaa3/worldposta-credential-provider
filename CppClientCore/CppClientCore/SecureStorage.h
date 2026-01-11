#pragma once
/**
 * SecureStorage.h - DPAPI-based secure storage for sensitive data
 *
 * Uses Windows Data Protection API (DPAPI) to encrypt/decrypt sensitive values
 * stored in the registry. This prevents plaintext exposure of API keys and secrets.
 */

#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>

#pragma comment(lib, "crypt32.lib")

class SecureStorage {
public:
    /**
     * Encrypt a string using DPAPI and return base64-encoded result
     * Uses CRYPTPROTECT_LOCAL_MACHINE flag so any process on this machine can decrypt
     * @param plaintext The string to encrypt
     * @return Base64-encoded encrypted data, or empty string on failure
     */
    static std::string Encrypt(const std::string& plaintext);

    /**
     * Decrypt a base64-encoded DPAPI-encrypted string
     * @param encryptedBase64 The base64-encoded encrypted data
     * @return Decrypted plaintext, or empty string on failure
     */
    static std::string Decrypt(const std::string& encryptedBase64);

    /**
     * Wide string versions for convenience
     */
    static std::wstring EncryptW(const std::wstring& plaintext);
    static std::wstring DecryptW(const std::wstring& encryptedBase64);

    /**
     * Read an encrypted value from registry and decrypt it
     * @param hKey Registry root key
     * @param subKey Registry subkey path
     * @param valueName Name of the value
     * @return Decrypted value, or empty string if not found or decryption fails
     */
    static std::wstring ReadEncryptedRegistryValue(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName);

    /**
     * Encrypt a value and write it to registry
     * @param hKey Registry root key
     * @param subKey Registry subkey path
     * @param valueName Name of the value
     * @param plaintext The plaintext value to encrypt and store
     * @return true on success, false on failure
     */
    static bool WriteEncryptedRegistryValue(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName, const std::wstring& plaintext);

private:
    static std::string Base64Encode(const BYTE* data, size_t length);
    static std::vector<BYTE> Base64Decode(const std::string& encoded);
};
