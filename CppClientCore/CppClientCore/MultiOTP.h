/**
 * WorldPosta Credential Provider - Authentication Module Header
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
#pragma once
#include "OfflineHandler.h"
#include "Logger.h"
#include "Endpoint.h"
#include "PIConf.h"
#include "Codes.h"
#include "SecureString.h"
#include <Windows.h>
#include <string>
#include <map>
#include <functional>
#include <atomic>
#include "PrivacyIDEA.h"

class MultiOTP : public PrivacyIDEA {

public:
	MultiOTP(PICONFIG conf);

	// Verifies OTP with WorldPosta API
	// <returns> PI_AUTH_SUCCESS, PI_AUTH_FAILURE, PI_AUTH_ERROR </returns>
	HRESULT validateCheck(const std::wstring& username, const std::wstring& domain, const SecureWString& otp, const std::string& transaction_id, HRESULT& error_code, const std::wstring& usersid);

	// Returns user token type (push, totp, without2fa, etc.)
	HRESULT userTokenType(const std::wstring& username, const std::wstring& domain, const std::wstring& usersid);

	// Send push notification via WorldPosta API
	HRESULT sendPushNotification(const std::wstring& username, const std::wstring& domain);

	// Check push notification status
	HRESULT checkPushStatus();

private:

};