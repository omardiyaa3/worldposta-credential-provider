#pragma once

#include <Windows.h>
#include <string>
#include <functional>
#include <CommCtrl.h>

// Auth method choice result
enum class AuthMethod {
    PUSH = 1,
    OTP = 2,
    CANCEL = 0
};

// Dialog result for push
enum class PushResult {
    APPROVED = 1,
    DENIED = 2,
    TIMEOUT = 3,
    PUSH_FAILED = 0
};

// Callback types for push and OTP verification
using PushCallback = std::function<void()>;  // Called when push button clicked
using OTPVerifyCallback = std::function<bool(const std::wstring& code)>;  // Returns true if OTP valid

class AuthDialog {
public:
    // Set callbacks for push and OTP (call before ShowAuthChoiceDialog)
    static void SetPushCallback(PushCallback callback);
    static void SetOTPVerifyCallback(OTPVerifyCallback callback);
    // Show auth method choice dialog
    // Returns AuthMethod::PUSH, AuthMethod::OTP, or AuthMethod::CANCEL
    static AuthMethod ShowAuthChoiceDialog(HWND parent);

    // Show OTP input dialog
    // Returns the entered OTP code, or empty string if cancelled
    static std::wstring ShowOTPInputDialog(HWND parent);

    // Show "Waiting for push approval" dialog
    // This is non-modal and should be closed when push completes
    static HWND ShowPushWaitingDialog(HWND parent);

    // Close the push waiting dialog
    static void ClosePushWaitingDialog(HWND hwnd);

    // Show push result dialog
    static void ShowPushResultDialog(HWND parent, PushResult result);

    // Notify the dialog of push result (called from push polling thread)
    static void NotifyPushResult(bool approved);

    // Check if dialog is waiting for push
    static bool IsWaitingForPush();
};
