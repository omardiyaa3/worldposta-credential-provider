/**
 * WorldPosta Credential Provider - Authentication Module
 *
 * Modified for WorldPosta Authenticator integration
 * Original multiOTP code by SysCo systemes de communication sa
 *
 * @author    WorldPosta
 * @version   1.0.0
 * @date      2026-01-10
 * @copyright Apache License, Version 2.0
 *
 *********************************************************************/
#include "MultiotpHelpers.h"
#include "MultiOTP.h"
#include "OfflineHandler.h"
#include "Logger.h"
#include "Endpoint.h"
#include "PIConf.h"
#include "Codes.h"
#include "SecureString.h"
#include <Windows.h>
#include <winhttp.h>
#include <string>
#include <map>
#include <functional>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <bcrypt.h>
#include "MultiotpRegistry.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

using namespace std;

// Global variables for storing push request state
static std::string g_lastPushRequestId;
static std::wstring g_lastPushUsername;

// Helper function: Convert wstring to string (UTF-8)
static std::string WStringToString(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), NULL, 0, NULL, NULL);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &result[0], size_needed, NULL, NULL);
    return result;
}

// Helper function: Convert string to wstring
static std::wstring StringToWString(const std::string& s) {
    if (s.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], size_needed);
    return result;
}

// Helper function: Generate HMAC-SHA256 signature
static std::string GenerateHmacSha256(const std::string& key, const std::string& data) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    DWORD hashLength = 32; // SHA256 produces 32 bytes
    std::vector<BYTE> hash(hashLength);
    std::string result;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        DebugPrint("BCryptOpenAlgorithmProvider failed");
        return "";
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key.c_str(), (ULONG)key.length(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        DebugPrint("BCryptCreateHash failed");
        return "";
    }

    status = BCryptHashData(hHash, (PUCHAR)data.c_str(), (ULONG)data.length(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        DebugPrint("BCryptHashData failed");
        return "";
    }

    status = BCryptFinishHash(hHash, hash.data(), hashLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        DebugPrint("BCryptFinishHash failed");
        return "";
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Convert to hex string
    std::stringstream ss;
    for (DWORD i = 0; i < hashLength; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    }

    return ss.str();
}

// Helper function: Make HTTP request to WorldPosta API
static std::string WorldPostaApiRequest(const std::wstring& endpoint, const std::string& path,
                                        const std::string& body, const std::string& integrationKey,
                                        const std::string& secretKey, const std::string& method = "POST") {
    std::string response;

    // Parse endpoint URL
    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[256] = {0};
    wchar_t urlPath[1024] = {0};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(endpoint.c_str(), 0, 0, &urlComp)) {
        DebugPrint("Failed to parse endpoint URL");
        return "";
    }

    // Open WinHTTP session
    HINTERNET hSession = WinHttpOpen(L"WorldPosta-CredentialProvider/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        DebugPrint("WinHttpOpen failed");
        return "";
    }

    // Connect to server
    INTERNET_PORT port = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    if (urlComp.nPort != 0) port = urlComp.nPort;

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        DebugPrint("WinHttpConnect failed");
        return "";
    }

    // Build full path
    std::wstring fullPath = urlPath;
    fullPath += StringToWString(path);

    // Open request
    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, StringToWString(method).c_str(),
                                           fullPath.c_str(), NULL,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        DebugPrint("WinHttpOpenRequest failed");
        return "";
    }

    // Generate timestamp and signature
    time_t now = time(nullptr);
    std::string timestamp = std::to_string(now);
    std::string signatureData = timestamp + body;
    std::string signature = GenerateHmacSha256(secretKey, signatureData);

    // Add headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"X-Integration-Key: " + StringToWString(integrationKey) + L"\r\n";
    headers += L"X-Signature: " + StringToWString(signature) + L"\r\n";
    headers += L"X-Timestamp: " + StringToWString(timestamp) + L"\r\n";

    WinHttpAddRequestHeaders(hRequest, headers.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    // Send request
    BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     (LPVOID)body.c_str(), (DWORD)body.length(),
                                     (DWORD)body.length(), 0);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        DebugPrint("WinHttpSendRequest failed");
        return "";
    }

    // Receive response
    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        DebugPrint("WinHttpReceiveResponse failed");
        return "";
    }

    // Read response
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;

        char* buffer = new char[dwSize + 1];
        ZeroMemory(buffer, dwSize + 1);

        if (WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
            response.append(buffer, dwDownloaded);
        }
        delete[] buffer;
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    DebugPrint(("WorldPosta API Response: " + response).c_str());
    return response;
}

// Simple JSON value extractor
static std::string GetJsonValue(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) return "";

    size_t colonPos = json.find(':', keyPos);
    if (colonPos == std::string::npos) return "";

    size_t valueStart = json.find_first_not_of(" \t\n\r", colonPos + 1);
    if (valueStart == std::string::npos) return "";

    if (json[valueStart] == '"') {
        // String value
        size_t valueEnd = json.find('"', valueStart + 1);
        if (valueEnd == std::string::npos) return "";
        return json.substr(valueStart + 1, valueEnd - valueStart - 1);
    } else if (json[valueStart] == 't' || json[valueStart] == 'f') {
        // Boolean value
        if (json.substr(valueStart, 4) == "true") return "true";
        if (json.substr(valueStart, 5) == "false") return "false";
    }

    // Number or other
    size_t valueEnd = json.find_first_of(",}]", valueStart);
    if (valueEnd == std::string::npos) return "";
    return json.substr(valueStart, valueEnd - valueStart);
}

MultiOTP::MultiOTP(PICONFIG conf):PrivacyIDEA(conf)
{
}

HRESULT MultiOTP::validateCheck(const std::wstring& username, const std::wstring& domain, const SecureWString& otp, const std::string& transaction_id, HRESULT& error_code, const std::wstring& usersid)
{
    PrintLn("=== WorldPosta::validateCheck START ===");
    PrintLn(L"User: ", username.c_str());
    PrintLn(L"OTP: ", otp.c_str());

    HRESULT hr = E_UNEXPECTED;
    error_code = 0;

    // Read WorldPosta configuration from registry
    PWSTR endpoint = nullptr;
    PWSTR integrationKey = nullptr;
    PWSTR secretKey = nullptr;

    DWORD epLen = readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_api_endpoint", &endpoint, L"");
    DWORD ikLen = readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_integration_key", &integrationKey, L"");
    DWORD skLen = readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_secret_key", &secretKey, L"");

    PrintLn(("Registry read - endpoint:" + std::to_string(epLen) + " ik:" + std::to_string(ikLen) + " sk:" + std::to_string(skLen)).c_str());

    if (epLen < 2 || ikLen < 2 || skLen < 2) {
        PrintLn("WorldPosta configuration NOT found in registry - FAIL");
        error_code = 99;
        return PI_AUTH_FAILURE;
    }

    PrintLn(L"Endpoint: ", endpoint);

    std::wstring wsEndpoint = endpoint;
    std::string sIntegrationKey = WStringToString(integrationKey);
    std::string sSecretKey = WStringToString(secretKey);

    // Clean username (remove domain prefix if present)
    std::wstring cleanUsername = getCleanUsername(username, domain);
    std::string sUsername = WStringToString(cleanUsername);

    // Convert OTP to string
    std::string sOtp = WStringToString(std::wstring(otp.c_str()));

    // Check if this is a push authentication request
    if (sOtp == "push" || sOtp == "sms") {
        if (DEVELOP_MODE) PrintLn(("Push authentication requested for user " + sUsername).c_str());

        // Send push notification
        HRESULT pushResult = sendPushNotification(username, domain);
        if (FAILED(pushResult)) {
            if (DEVELOP_MODE) PrintLn("Failed to send push notification");
            error_code = 70;
            return PI_AUTH_FAILURE;
        }

        // Poll for push status with timeout (60 seconds, checking every 2 seconds)
        const int maxAttempts = 30;
        const int pollIntervalMs = 2000;

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            Sleep(pollIntervalMs);

            HRESULT status = checkPushStatus();

            if (status == PI_AUTH_SUCCESS) {
                if (DEVELOP_MODE) PrintLn("Push authentication SUCCESS");
                return PI_AUTH_SUCCESS;
            }
            else if (status == PI_AUTH_FAILURE) {
                if (DEVELOP_MODE) PrintLn("Push authentication DENIED or EXPIRED");
                error_code = 99;
                return PI_AUTH_FAILURE;
            }
            // E_PENDING means keep polling
            if (DEVELOP_MODE) PrintLn(("Push polling attempt " + std::to_string(attempt + 1) + "/" + std::to_string(maxAttempts)).c_str());
        }

        // Timeout - no response within time limit
        if (DEVELOP_MODE) PrintLn("Push authentication TIMEOUT");
        error_code = 70;
        return PI_AUTH_FAILURE;
    }

    // Standard TOTP verification
    // Build JSON request body
    std::string requestBody = "{\"externalUserId\":\"" + sUsername + "\",\"code\":\"" + sOtp + "\"}";

    if (DEVELOP_MODE) PrintLn(("Calling WorldPosta API: /v1/totp/verify for user " + sUsername).c_str());

    // Call WorldPosta API
    std::string response = WorldPostaApiRequest(wsEndpoint, "/v1/totp/verify",
                                                requestBody, sIntegrationKey, sSecretKey);

    if (response.empty()) {
        if (DEVELOP_MODE) PrintLn("WorldPosta API returned empty response");
        error_code = 70; // Server authentication error
        return PI_AUTH_FAILURE;
    }

    // Parse response
    std::string valid = GetJsonValue(response, "valid");

    if (valid == "true") {
        if (DEVELOP_MODE) PrintLn("WorldPosta TOTP verification SUCCESS");
        return PI_AUTH_SUCCESS;
    } else {
        if (DEVELOP_MODE) PrintLn("WorldPosta TOTP verification FAILED");
        error_code = 99;
        return PI_AUTH_FAILURE;
    }
}

/**
Return user token type :
    6: push token
    7: with token
    8: without2FA
    21: User doesn't exist
    24: user locked
    25: delayed
    38: User disabled
    81: Cache too old
    99: error
*/
HRESULT MultiOTP::userTokenType(const std::wstring& username, const std::wstring& domain, const std::wstring& usersid)
{
    PrintLn("=== WorldPosta::userTokenType START ===");
    PrintLn(L"User: ", username.c_str());

    // For WorldPosta, all enrolled users have push capability
    // Return MULTIOTP_IS_PUSH_TOKEN (6) to enable push option
    // The actual check would require an API call, but for now we assume push is available

    // Read WorldPosta configuration from registry
    PWSTR endpoint = nullptr;
    PWSTR integrationKey = nullptr;
    PWSTR secretKey = nullptr;

    DWORD epLen = readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_api_endpoint", &endpoint, L"");
    DWORD ikLen = readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_integration_key", &integrationKey, L"");
    DWORD skLen = readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_secret_key", &secretKey, L"");

    PrintLn(("Registry read lengths - endpoint:" + std::to_string(epLen) +
             " integrationKey:" + std::to_string(ikLen) +
             " secretKey:" + std::to_string(skLen)).c_str());

    if (endpoint) PrintLn(L"Endpoint: ", endpoint);
    if (integrationKey) PrintLn(L"IntegrationKey: ", integrationKey);
    if (secretKey) PrintLn("SecretKey: [present]");

    if (epLen < 2 || ikLen < 2 || skLen < 2) {
        PrintLn("WorldPosta configuration not found - returning MULTIOTP_IS_WITH_TOKEN (7)");
        return MULTIOTP_IS_WITH_TOKEN; // Return 7 - user has TOTP token
    }

    // WorldPosta users have both push and TOTP capability
    PrintLn("WorldPosta configured - returning MULTIOTP_IS_PUSH_TOKEN (6)");
    return MULTIOTP_IS_PUSH_TOKEN; // Return 6 - push token available
}

// Send push notification via WorldPosta API
HRESULT MultiOTP::sendPushNotification(const std::wstring& username, const std::wstring& domain)
{
    if (DEVELOP_MODE) PrintLn(L"WorldPosta::sendPushNotification for user: ", username.c_str());

    // Read WorldPosta configuration from registry
    PWSTR endpoint = nullptr;
    PWSTR integrationKey = nullptr;
    PWSTR secretKey = nullptr;

    if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_api_endpoint", &endpoint, L"") < 2 ||
        readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_integration_key", &integrationKey, L"") < 2 ||
        readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_secret_key", &secretKey, L"") < 2) {
        if (DEVELOP_MODE) PrintLn("WorldPosta configuration not found");
        return E_FAIL;
    }

    std::wstring wsEndpoint = endpoint;
    std::string sIntegrationKey = WStringToString(integrationKey);
    std::string sSecretKey = WStringToString(secretKey);

    // Clean username
    std::wstring cleanUsername = getCleanUsername(username, domain);
    std::string sUsername = WStringToString(cleanUsername);

    // Build JSON request body
    std::string requestBody = "{\"externalUserId\":\"" + sUsername +
                              "\",\"serviceName\":\"Windows RDP Login\"" +
                              ",\"deviceInfo\":\"Windows Credential Provider\"}";

    // Call WorldPosta API
    std::string response = WorldPostaApiRequest(wsEndpoint, "/v1/push/send",
                                                requestBody, sIntegrationKey, sSecretKey);

    if (response.empty()) {
        if (DEVELOP_MODE) PrintLn("WorldPosta push API returned empty response");
        return E_FAIL;
    }

    // Parse response to get requestId
    std::string requestId = GetJsonValue(response, "requestId");
    if (requestId.empty()) {
        if (DEVELOP_MODE) PrintLn("Failed to get push requestId");
        return E_FAIL;
    }

    // Store for later polling
    g_lastPushRequestId = requestId;
    g_lastPushUsername = cleanUsername;

    if (DEVELOP_MODE) PrintLn(("Push notification sent, requestId: " + requestId).c_str());
    return S_OK;
}

// Check push notification status
HRESULT MultiOTP::checkPushStatus()
{
    if (g_lastPushRequestId.empty()) {
        return E_FAIL;
    }

    // Read WorldPosta configuration from registry
    PWSTR endpoint = nullptr;
    PWSTR integrationKey = nullptr;
    PWSTR secretKey = nullptr;

    if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_api_endpoint", &endpoint, L"") < 2 ||
        readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_integration_key", &integrationKey, L"") < 2 ||
        readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, L"worldposta_secret_key", &secretKey, L"") < 2) {
        return E_FAIL;
    }

    std::wstring wsEndpoint = endpoint;
    std::string sIntegrationKey = WStringToString(integrationKey);
    std::string sSecretKey = WStringToString(secretKey);

    // Build path with requestId
    std::string path = "/v1/push/status/" + g_lastPushRequestId;

    // Call WorldPosta API (GET request, empty body)
    std::string response = WorldPostaApiRequest(wsEndpoint, path, "{}", sIntegrationKey, sSecretKey, "GET");

    if (response.empty()) {
        return E_FAIL;
    }

    // Parse response
    std::string status = GetJsonValue(response, "status");

    if (status == "approved") {
        if (DEVELOP_MODE) PrintLn("Push notification APPROVED");
        g_lastPushRequestId.clear();
        return PI_AUTH_SUCCESS;
    } else if (status == "denied") {
        if (DEVELOP_MODE) PrintLn("Push notification DENIED");
        g_lastPushRequestId.clear();
        return PI_AUTH_FAILURE;
    } else if (status == "expired") {
        if (DEVELOP_MODE) PrintLn("Push notification EXPIRED");
        g_lastPushRequestId.clear();
        return PI_AUTH_FAILURE;
    }

    // Still pending
    return E_PENDING;
}
