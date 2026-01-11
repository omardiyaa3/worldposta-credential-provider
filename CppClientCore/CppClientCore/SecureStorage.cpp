#include "SecureStorage.h"
#include <vector>
#include <sstream>

// Base64 encoding table
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string SecureStorage::Base64Encode(const BYTE* data, size_t length) {
    std::string result;
    result.reserve(((length + 2) / 3) * 4);

    for (size_t i = 0; i < length; i += 3) {
        unsigned int n = data[i] << 16;
        if (i + 1 < length) n |= data[i + 1] << 8;
        if (i + 2 < length) n |= data[i + 2];

        result.push_back(base64_chars[(n >> 18) & 0x3F]);
        result.push_back(base64_chars[(n >> 12) & 0x3F]);
        result.push_back((i + 1 < length) ? base64_chars[(n >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < length) ? base64_chars[n & 0x3F] : '=');
    }

    return result;
}

std::vector<BYTE> SecureStorage::Base64Decode(const std::string& encoded) {
    std::vector<BYTE> result;
    if (encoded.empty()) return result;

    // Build decode table
    int decodeTable[256];
    memset(decodeTable, -1, sizeof(decodeTable));
    for (int i = 0; i < 64; i++) {
        decodeTable[(unsigned char)base64_chars[i]] = i;
    }

    result.reserve((encoded.size() / 4) * 3);

    unsigned int buffer = 0;
    int bits = 0;

    for (char c : encoded) {
        if (c == '=') break;
        int val = decodeTable[(unsigned char)c];
        if (val < 0) continue;

        buffer = (buffer << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            result.push_back((BYTE)((buffer >> bits) & 0xFF));
        }
    }

    return result;
}

std::string SecureStorage::Encrypt(const std::string& plaintext) {
    if (plaintext.empty()) return "";

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;

    dataIn.pbData = (BYTE*)plaintext.c_str();
    dataIn.cbData = (DWORD)(plaintext.length() + 1); // Include null terminator

    // Use CRYPTPROTECT_LOCAL_MACHINE so the credential provider (running as SYSTEM) can decrypt
    if (!CryptProtectData(&dataIn, NULL, NULL, NULL, NULL,
                          CRYPTPROTECT_LOCAL_MACHINE, &dataOut)) {
        return "";
    }

    std::string result = Base64Encode(dataOut.pbData, dataOut.cbData);
    LocalFree(dataOut.pbData);

    return result;
}

std::string SecureStorage::Decrypt(const std::string& encryptedBase64) {
    if (encryptedBase64.empty()) return "";

    std::vector<BYTE> encrypted = Base64Decode(encryptedBase64);
    if (encrypted.empty()) return "";

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;

    dataIn.pbData = encrypted.data();
    dataIn.cbData = (DWORD)encrypted.size();

    if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
        return "";
    }

    std::string result((char*)dataOut.pbData);

    // Securely clear the decrypted data before freeing
    SecureZeroMemory(dataOut.pbData, dataOut.cbData);
    LocalFree(dataOut.pbData);

    return result;
}

std::wstring SecureStorage::EncryptW(const std::wstring& plaintext) {
    if (plaintext.empty()) return L"";

    // Convert wstring to UTF-8 string for encryption
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, plaintext.c_str(), (int)plaintext.size(), NULL, 0, NULL, NULL);
    std::string utf8(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, plaintext.c_str(), (int)plaintext.size(), &utf8[0], size_needed, NULL, NULL);

    std::string encrypted = Encrypt(utf8);

    // Securely clear the UTF-8 string
    SecureZeroMemory(&utf8[0], utf8.size());

    // Convert result to wstring
    int wsize = MultiByteToWideChar(CP_UTF8, 0, encrypted.c_str(), (int)encrypted.size(), NULL, 0);
    std::wstring result(wsize, 0);
    MultiByteToWideChar(CP_UTF8, 0, encrypted.c_str(), (int)encrypted.size(), &result[0], wsize);

    return result;
}

std::wstring SecureStorage::DecryptW(const std::wstring& encryptedBase64) {
    if (encryptedBase64.empty()) return L"";

    // Convert wstring to string
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, encryptedBase64.c_str(), (int)encryptedBase64.size(), NULL, 0, NULL, NULL);
    std::string encrypted(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, encryptedBase64.c_str(), (int)encryptedBase64.size(), &encrypted[0], size_needed, NULL, NULL);

    std::string decrypted = Decrypt(encrypted);
    if (decrypted.empty()) return L"";

    // Convert decrypted UTF-8 back to wstring
    int wsize = MultiByteToWideChar(CP_UTF8, 0, decrypted.c_str(), (int)decrypted.size(), NULL, 0);
    std::wstring result(wsize, 0);
    MultiByteToWideChar(CP_UTF8, 0, decrypted.c_str(), (int)decrypted.size(), &result[0], wsize);

    // Securely clear the decrypted string
    SecureZeroMemory(&decrypted[0], decrypted.size());

    return result;
}

std::wstring SecureStorage::ReadEncryptedRegistryValue(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName) {
    HKEY hRegKey;
    if (RegOpenKeyExW(hKey, subKey, 0, KEY_READ, &hRegKey) != ERROR_SUCCESS) {
        return L"";
    }

    DWORD type;
    DWORD size = 0;

    // Get size first
    if (RegQueryValueExW(hRegKey, valueName, NULL, &type, NULL, &size) != ERROR_SUCCESS) {
        RegCloseKey(hRegKey);
        return L"";
    }

    if (type != REG_SZ || size == 0) {
        RegCloseKey(hRegKey);
        return L"";
    }

    std::vector<wchar_t> buffer(size / sizeof(wchar_t));
    if (RegQueryValueExW(hRegKey, valueName, NULL, &type, (LPBYTE)buffer.data(), &size) != ERROR_SUCCESS) {
        RegCloseKey(hRegKey);
        return L"";
    }

    RegCloseKey(hRegKey);

    std::wstring encryptedValue(buffer.data());
    return DecryptW(encryptedValue);
}

bool SecureStorage::WriteEncryptedRegistryValue(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName, const std::wstring& plaintext) {
    std::wstring encrypted = EncryptW(plaintext);
    if (encrypted.empty() && !plaintext.empty()) {
        return false; // Encryption failed
    }

    HKEY hRegKey;
    if (RegCreateKeyExW(hKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hRegKey, NULL) != ERROR_SUCCESS) {
        return false;
    }

    DWORD size = (DWORD)((encrypted.size() + 1) * sizeof(wchar_t));
    LONG result = RegSetValueExW(hRegKey, valueName, 0, REG_SZ, (const BYTE*)encrypted.c_str(), size);

    RegCloseKey(hRegKey);
    return result == ERROR_SUCCESS;
}
