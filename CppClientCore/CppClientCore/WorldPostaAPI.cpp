/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2024-2025 WorldPosta
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
** * * * * * * * * * * * * * * * * * * */

#include "WorldPostaAPI.h"
#include "Logger.h"
#include "../nlohmann/json.hpp"

#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

using namespace std;
using json = nlohmann::json;

WorldPostaAPI::WorldPostaAPI(WorldPostaConfig config) : _config(config)
{
    DebugPrint("WorldPostaAPI initialized");
    DebugPrint("API Endpoint: " + ws2s(_config.apiEndpoint));
}

std::string WorldPostaAPI::normalizeUsername(const std::wstring& username)
{
    std::string user = ws2s(username);

    // Handle DOMAIN\username format
    size_t pos = user.find('\\');
    if (pos != std::string::npos) {
        user = user.substr(pos + 1);
    }

    // Handle username@domain format
    pos = user.find('@');
    if (pos != std::string::npos) {
        user = user.substr(0, pos);
    }

    // Convert to lowercase
    std::transform(user.begin(), user.end(), user.begin(), ::tolower);

    return user;
}

std::string WorldPostaAPI::generateSignature(const std::string& timestamp, const std::string& body)
{
    std::string dataToSign = timestamp + body;
    std::string secretKey = ws2s(_config.secretKey);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    DWORD hashLength = 32;
    BYTE hash[32];

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        DebugPrint("BCryptOpenAlgorithmProvider failed");
        return "";
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0,
        (PUCHAR)secretKey.c_str(), (ULONG)secretKey.length(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    status = BCryptHashData(hHash, (PUCHAR)dataToSign.c_str(), (ULONG)dataToSign.length(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    status = BCryptFinishHash(hHash, hash, hashLength, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        return "";
    }

    std::stringstream ss;
    for (DWORD i = 0; i < hashLength; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

std::string WorldPostaAPI::makeRequest(
    const std::string& method,
    const std::string& endpoint,
    const std::string& body)
{
    DebugPrint("WorldPostaAPI::makeRequest");
    DebugPrint("Method: " + method);
    DebugPrint("Endpoint: " + endpoint);

    std::wstring wUrl = _config.apiEndpoint;
    std::wstring wHostname;
    int port = INTERNET_DEFAULT_HTTPS_PORT;

    // Parse URL
    size_t protocolEnd = wUrl.find(L"://");
    if (protocolEnd != std::wstring::npos) {
        wUrl = wUrl.substr(protocolEnd + 3);
    }

    size_t pathStart = wUrl.find(L'/');
    if (pathStart != std::wstring::npos) {
        wHostname = wUrl.substr(0, pathStart);
    } else {
        wHostname = wUrl;
    }

    size_t portStart = wHostname.find(L':');
    if (portStart != std::wstring::npos) {
        port = std::stoi(wHostname.substr(portStart + 1));
        wHostname = wHostname.substr(0, portStart);
    }

    std::wstring wPath = s2ws(endpoint);

    // Generate timestamp and signature
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
    std::string timestamp = std::to_string(seconds);
    std::string signature = generateSignature(timestamp, body);

    // WinHTTP setup
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    std::string response;

    hSession = WinHttpOpen(L"WorldPosta-CredentialProvider/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        _lastError = WP_SETUP_ERROR;
        _lastErrorMessage = L"Failed to initialize HTTP";
        return "";
    }

    WinHttpSetTimeouts(hSession, 0, 30000, 30000, _config.timeout * 1000);

    hConnect = WinHttpConnect(hSession, wHostname.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        _lastError = WP_SERVER_UNAVAILABLE;
        _lastErrorMessage = L"Failed to connect";
        return "";
    }

    std::wstring wMethod = s2ws(method);
    hRequest = WinHttpOpenRequest(hConnect, wMethod.c_str(), wPath.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        _lastError = WP_SETUP_ERROR;
        return "";
    }

    // Build headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"X-Integration-Key: " + _config.integrationKey + L"\r\n";
    headers += L"X-Signature: " + s2ws(signature) + L"\r\n";
    headers += L"X-Timestamp: " + s2ws(timestamp) + L"\r\n";

    BOOL bResults = WinHttpSendRequest(hRequest,
        headers.c_str(), (DWORD)-1L,
        (LPVOID)body.c_str(), (DWORD)body.length(),
        (DWORD)body.length(), 0);

    if (!bResults) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        _lastError = WP_SERVER_UNAVAILABLE;
        return "";
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        _lastError = WP_SERVER_UNAVAILABLE;
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

    DebugPrint("Response: " + response);
    return response;
}

HRESULT WorldPostaAPI::verifyTOTP(
    const std::wstring& username,
    const std::wstring& domain,
    const SecureWString& code,
    const std::wstring& userSID)
{
    DebugPrint("WorldPostaAPI::verifyTOTP");

    std::string normalizedUser = normalizeUsername(username);

    json requestBody;
    requestBody["externalUserId"] = normalizedUser;
    requestBody["code"] = ws2s(std::wstring(code.c_str()));

    std::string body = requestBody.dump();
    std::string response = makeRequest("POST", WP_ENDPOINT_TOTP_VERIFY, body);

    if (response.empty()) {
        return _lastError;
    }

    try {
        json j = json::parse(response);

        if (j.contains("valid") && j["valid"].get<bool>()) {
            DebugPrint("TOTP verification successful");
            return WP_AUTH_SUCCESS;
        } else {
            DebugPrint("TOTP verification failed");
            if (j.contains("message")) {
                _lastErrorMessage = s2ws(j["message"].get<std::string>());
            }
            return WP_AUTH_FAILURE;
        }
    } catch (const json::exception& e) {
        DebugPrint("JSON parse error");
        _lastError = WP_AUTH_ERROR;
        return WP_AUTH_ERROR;
    }
}

HRESULT WorldPostaAPI::sendPush(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& hostname,
    const std::wstring& userSID)
{
    DebugPrint("WorldPostaAPI::sendPush");

    std::string normalizedUser = normalizeUsername(username);

    json requestBody;
    requestBody["externalUserId"] = normalizedUser;
    requestBody["serviceName"] = "Windows RDP Login";
    requestBody["deviceInfo"] = ws2s(hostname) + " (Windows)";
    requestBody["loginType"] = "rdp";

    std::string body = requestBody.dump();
    std::string response = makeRequest("POST", WP_ENDPOINT_PUSH_SEND, body);

    if (response.empty()) {
        return _lastError;
    }

    try {
        json j = json::parse(response);

        if (j.contains("requestId")) {
            _currentChallenge.requestId = j["requestId"].get<std::string>();
            _currentChallenge.status = "pending";
            _currentChallenge.expiresIn = j.value("expiresIn", 60);
            DebugPrint("Push sent, requestId: " + _currentChallenge.requestId);
            return WP_TRIGGERED_PUSH;
        } else if (j.contains("error")) {
            _lastErrorMessage = s2ws(j["error"].get<std::string>());
            if (j["error"] == "user_not_found") {
                return WP_USER_NOT_FOUND;
            }
            return WP_AUTH_ERROR;
        }
        return WP_AUTH_ERROR;
    } catch (const json::exception& e) {
        _lastError = WP_AUTH_ERROR;
        return WP_AUTH_ERROR;
    }
}

HRESULT WorldPostaAPI::checkPushStatus(const std::string& requestId)
{
    std::string endpoint = std::string(WP_ENDPOINT_PUSH_STATUS) + requestId;
    std::string response = makeRequest("GET", endpoint, "");

    if (response.empty()) {
        return _lastError;
    }

    try {
        json j = json::parse(response);
        std::string status = j.value("status", "pending");

        if (status == "approved") return WP_PUSH_APPROVED;
        if (status == "denied") return WP_PUSH_DENIED;
        if (status == "expired") return WP_PUSH_EXPIRED;
        return WP_PUSH_PENDING;
    } catch (const json::exception& e) {
        return WP_AUTH_ERROR;
    }
}

void WorldPostaAPI::pollThread(
    const std::string& requestId,
    std::function<void(bool)> callback)
{
    DebugPrint("Starting push poll thread...");

    int pollCount = 0;
    int maxPolls = _currentChallenge.expiresIn * 2;

    while (_runPoll.load() && pollCount < maxPolls) {
        HRESULT status = checkPushStatus(requestId);

        if (status == WP_PUSH_APPROVED) {
            DebugPrint("Push approved!");
            callback(true);
            _runPoll.store(false);
            return;
        } else if (status == WP_PUSH_DENIED || status == WP_PUSH_EXPIRED) {
            DebugPrint("Push denied or expired");
            callback(false);
            _runPoll.store(false);
            return;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        pollCount++;
    }

    DebugPrint("Push polling stopped or timed out");
    callback(false);
}

void WorldPostaAPI::asyncPollPush(
    const std::string& requestId,
    std::function<void(bool)> callback)
{
    _runPoll.store(true);
    std::thread t(&WorldPostaAPI::pollThread, this, requestId, callback);
    t.detach();
}

bool WorldPostaAPI::stopPoll()
{
    _runPoll.store(false);
    return true;
}

HRESULT WorldPostaAPI::getAuthMethods(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& userSID,
    bool& totpAvailable,
    bool& pushAvailable)
{
    std::string normalizedUser = normalizeUsername(username);

    wchar_t hostname[256];
    DWORD size = 256;
    GetComputerNameW(hostname, &size);

    json requestBody;
    requestBody["externalUserId"] = normalizedUser;
    requestBody["hostname"] = ws2s(std::wstring(hostname));
    requestBody["loginType"] = "rdp";

    std::string body = requestBody.dump();
    std::string response = makeRequest("POST", WP_ENDPOINT_RDP_AUTH, body);

    if (response.empty()) {
        totpAvailable = _config.totpEnabled;
        pushAvailable = _config.pushEnabled;
        return _lastError;
    }

    try {
        json j = json::parse(response);

        if (j.contains("success") && j["success"].get<bool>()) {
            totpAvailable = j.value("totpEnabled", true);
            pushAvailable = j.value("pushEnabled", true);
            return WP_AUTH_SUCCESS;
        } else if (j.contains("error") && j["error"] == "user_not_found") {
            totpAvailable = false;
            pushAvailable = false;
            return WP_USER_NOT_FOUND;
        }
        return WP_AUTH_ERROR;
    } catch (const json::exception& e) {
        totpAvailable = _config.totpEnabled;
        pushAvailable = _config.pushEnabled;
        return WP_AUTH_ERROR;
    }
}

std::wstring WorldPostaAPI::s2ws(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], size);
    return result;
}

std::string WorldPostaAPI::ws2s(const std::wstring& ws)
{
    if (ws.empty()) return std::string();
    int size = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), NULL, 0, NULL, NULL);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &result[0], size, NULL, NULL);
    return result;
}

std::wstring WorldPostaAPI::toUpperCase(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}
