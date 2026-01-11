#pragma once

#include <Windows.h>
#include <string>
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

class AuthDialog {
public:
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
};
