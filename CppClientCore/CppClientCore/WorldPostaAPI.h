/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2024-2025 WorldPosta
** Based on PrivacyIDEA by NetKnights GmbH
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
** * * * * * * * * * * * * * * * * * * */

#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <map>
#include "SecureString.h"

// Status codes
#define WP_AUTH_SUCCESS          0x00000000
#define WP_AUTH_FAILURE          0x00000001
#define WP_AUTH_ERROR            0x00000002
#define WP_TRIGGERED_PUSH        0x00000003
#define WP_PUSH_APPROVED         0x00000004
#define WP_PUSH_DENIED           0x00000005
#define WP_PUSH_EXPIRED          0x00000006
#define WP_PUSH_PENDING          0x00000007
#define WP_SERVER_UNAVAILABLE    0x00000010
#define WP_SETUP_ERROR           0x00000011
#define WP_USER_NOT_FOUND        0x00000012
#define WP_USER_LOCKED           0x00000013

// API Endpoints
#define WP_ENDPOINT_TOTP_VERIFY  "/v1/totp/verify"
#define WP_ENDPOINT_PUSH_SEND    "/v1/push/send"
#define WP_ENDPOINT_PUSH_STATUS  "/v1/push/status/"
#define WP_ENDPOINT_RDP_AUTH     "/v1/rdp/auth"

struct WorldPostaConfig
{
    std::wstring apiEndpoint = L"https://api.worldposta.com";
    std::wstring integrationKey = L"";
    std::wstring secretKey = L"";
    int timeout = 60;
    bool pushEnabled = true;
    bool totpEnabled = true;
    bool logPasswords = false;
};

struct PushChallenge
{
    std::string requestId;
    std::string status;
    int expiresIn = 60;

    std::string toString() const {
        return "requestId=" + requestId + ", status=" + status;
    }
};

enum class AuthMethod
{
    TOTP,
    PUSH,
    NONE
};

class WorldPostaAPI
{
public:
    WorldPostaAPI(WorldPostaConfig config);
    ~WorldPostaAPI() = default;

    // Verify TOTP code
    HRESULT verifyTOTP(
        const std::wstring& username,
        const std::wstring& domain,
        const SecureWString& code,
        const std::wstring& userSID
    );

    // Send push notification
    HRESULT sendPush(
        const std::wstring& username,
        const std::wstring& domain,
        const std::wstring& hostname,
        const std::wstring& userSID
    );

    // Poll for push status
    HRESULT checkPushStatus(const std::string& requestId);

    // Start async polling for push approval
    void asyncPollPush(
        const std::string& requestId,
        std::function<void(bool)> callback
    );

    // Stop polling
    bool stopPoll();

    // Get current push challenge
    PushChallenge getCurrentChallenge() const { return _currentChallenge; }

    // Get available auth methods for user
    HRESULT getAuthMethods(
        const std::wstring& username,
        const std::wstring& domain,
        const std::wstring& userSID,
        bool& totpAvailable,
        bool& pushAvailable
    );

    // Error handling
    int getLastError() const { return _lastError; }
    std::wstring getLastErrorMessage() const { return _lastErrorMessage; }

    // Utility functions
    static std::wstring s2ws(const std::string& s);
    static std::string ws2s(const std::wstring& ws);
    static std::wstring toUpperCase(std::wstring s);

private:
    WorldPostaConfig _config;
    PushChallenge _currentChallenge;
    std::atomic<bool> _runPoll{ false };
    int _lastError = 0;
    std::wstring _lastErrorMessage;

    std::string makeRequest(
        const std::string& method,
        const std::string& endpoint,
        const std::string& body
    );

    std::string generateSignature(
        const std::string& timestamp,
        const std::string& body
    );

    std::string normalizeUsername(const std::wstring& username);

    void pollThread(
        const std::string& requestId,
        std::function<void(bool)> callback
    );
};
