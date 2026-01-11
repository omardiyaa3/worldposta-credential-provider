#include "AuthDialog.h"
#include <CommCtrl.h>
#include <windowsx.h>

#pragma comment(lib, "comctl32.lib")

// Dialog control IDs
#define IDC_OTP_EDIT 1001
#define IDC_OK_BUTTON 1002
#define IDC_CANCEL_BUTTON 1003
#define IDC_PUSH_BUTTON 1004
#define IDC_OTP_BUTTON 1005
#define IDC_WAITING_TEXT 1006

// Global to store OTP result
static std::wstring g_otpResult;
static AuthMethod g_authChoice = AuthMethod::CANCEL;

// Auth choice dialog procedure
static INT_PTR CALLBACK AuthChoiceDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        // Center the dialog
        {
            RECT rc;
            GetWindowRect(hwnd, &rc);
            int w = rc.right - rc.left;
            int h = rc.bottom - rc.top;
            int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
            int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
            SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0, SWP_NOSIZE);
        }
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_PUSH_BUTTON:
            g_authChoice = AuthMethod::PUSH;
            EndDialog(hwnd, IDC_PUSH_BUTTON);
            return TRUE;
        case IDC_OTP_BUTTON:
            g_authChoice = AuthMethod::OTP;
            EndDialog(hwnd, IDC_OTP_BUTTON);
            return TRUE;
        case IDCANCEL:
            g_authChoice = AuthMethod::CANCEL;
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        g_authChoice = AuthMethod::CANCEL;
        EndDialog(hwnd, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

// OTP input dialog procedure
static INT_PTR CALLBACK OTPInputDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        // Center the dialog
        {
            RECT rc;
            GetWindowRect(hwnd, &rc);
            int w = rc.right - rc.left;
            int h = rc.bottom - rc.top;
            int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
            int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
            SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0, SWP_NOSIZE);
        }
        // Focus on the edit control
        SetFocus(GetDlgItem(hwnd, IDC_OTP_EDIT));
        return FALSE; // Return FALSE because we set focus manually

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
        case IDC_OK_BUTTON:
            {
                wchar_t buffer[64] = {0};
                GetDlgItemTextW(hwnd, IDC_OTP_EDIT, buffer, 64);
                g_otpResult = buffer;
                EndDialog(hwnd, IDOK);
            }
            return TRUE;
        case IDCANCEL:
        case IDC_CANCEL_BUTTON:
            g_otpResult = L"";
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        g_otpResult = L"";
        EndDialog(hwnd, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

// Create auth choice dialog dynamically
AuthMethod AuthDialog::ShowAuthChoiceDialog(HWND parent) {
    g_authChoice = AuthMethod::CANCEL;

    // Create dialog template in memory
    HGLOBAL hgbl = GlobalAlloc(GMEM_ZEROINIT, 1024);
    if (!hgbl) return AuthMethod::CANCEL;

    LPDLGTEMPLATE lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl);

    // Dialog template
    lpdt->style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_CENTER;
    lpdt->cdit = 3;  // 3 controls: title text, push button, otp button
    lpdt->x = 0;
    lpdt->y = 0;
    lpdt->cx = 200;
    lpdt->cy = 100;

    LPWORD lpw = (LPWORD)(lpdt + 1);
    *lpw++ = 0; // No menu
    *lpw++ = 0; // Default dialog class

    // Dialog title
    LPWSTR lpwsz = (LPWSTR)lpw;
    wcscpy_s(lpwsz, 50, L"WorldPosta Authentication");
    lpw = (LPWORD)(lpwsz + wcslen(lpwsz) + 1);

    // Align to DWORD
    lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3);

    // Static text control
    LPDLGITEMTEMPLATE lpdit = (LPDLGITEMTEMPLATE)lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | SS_CENTER;
    lpdit->x = 10;
    lpdit->y = 10;
    lpdit->cx = 180;
    lpdit->cy = 20;
    lpdit->id = 0xFFFF;

    lpw = (LPWORD)(lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0082;  // Static class

    lpwsz = (LPWSTR)lpw;
    wcscpy_s(lpwsz, 50, L"Choose authentication method:");
    lpw = (LPWORD)(lpwsz + wcslen(lpwsz) + 1);
    *lpw++ = 0; // No creation data

    // Align to DWORD
    lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3);

    // Push button
    lpdit = (LPDLGITEMTEMPLATE)lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP;
    lpdit->x = 20;
    lpdit->y = 45;
    lpdit->cx = 70;
    lpdit->cy = 25;
    lpdit->id = IDC_PUSH_BUTTON;

    lpw = (LPWORD)(lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0080;  // Button class

    lpwsz = (LPWSTR)lpw;
    wcscpy_s(lpwsz, 20, L"Push");
    lpw = (LPWORD)(lpwsz + wcslen(lpwsz) + 1);
    *lpw++ = 0;

    // Align to DWORD
    lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3);

    // OTP button
    lpdit = (LPDLGITEMTEMPLATE)lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP;
    lpdit->x = 110;
    lpdit->y = 45;
    lpdit->cx = 70;
    lpdit->cy = 25;
    lpdit->id = IDC_OTP_BUTTON;

    lpw = (LPWORD)(lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0080;  // Button class

    lpwsz = (LPWSTR)lpw;
    wcscpy_s(lpwsz, 20, L"OTP");
    lpw = (LPWORD)(lpwsz + wcslen(lpwsz) + 1);
    *lpw++ = 0;

    GlobalUnlock(hgbl);

    DialogBoxIndirectW(NULL, (LPDLGTEMPLATE)hgbl, parent, AuthChoiceDlgProc);

    GlobalFree(hgbl);

    return g_authChoice;
}

// Create OTP input dialog dynamically
std::wstring AuthDialog::ShowOTPInputDialog(HWND parent) {
    g_otpResult = L"";

    // Create dialog template in memory
    HGLOBAL hgbl = GlobalAlloc(GMEM_ZEROINIT, 1024);
    if (!hgbl) return L"";

    LPDLGTEMPLATE lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl);

    // Dialog template
    lpdt->style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_CENTER;
    lpdt->cdit = 4;  // 4 controls: label, edit, ok button, cancel button
    lpdt->x = 0;
    lpdt->y = 0;
    lpdt->cx = 200;
    lpdt->cy = 90;

    LPWORD lpw = (LPWORD)(lpdt + 1);
    *lpw++ = 0;
    *lpw++ = 0;

    LPWSTR lpwsz = (LPWSTR)lpw;
    wcscpy_s(lpwsz, 50, L"Enter One-Time Password");
    lpw = (LPWORD)(lpwsz + wcslen(lpwsz) + 1);

    lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3);

    // Label
    LPDLGITEMTEMPLATE lpdit = (LPDLGITEMTEMPLATE)lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    lpdit->x = 10;
    lpdit->y = 10;
    lpdit->cx = 180;
    lpdit->cy = 12;
    lpdit->id = 0xFFFF;

    lpw = (LPWORD)(lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0082;

    lpwsz = (LPWSTR)lpw;
    wcscpy_s(lpwsz, 50, L"Enter the code from your app:");
    lpw = (LPWORD)(lpwsz + wcslen(lpwsz) + 1);
    *lpw++ = 0;

    lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3);

    // Edit control
    lpdit = (LPDLGITEMTEMPLATE)lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_CENTER | ES_NUMBER;
    lpdit->dwExtendedStyle = WS_EX_CLIENTEDGE;
    lpdit->x = 10;
    lpdit->y = 28;
    lpdit->cx = 180;
    lpdit->cy = 18;
    lpdit->id = IDC_OTP_EDIT;

    lpw = (LPWORD)(lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0081;  // Edit class

    lpwsz = (LPWSTR)lpw;
    *lpwsz = 0;
    lpw = (LPWORD)(lpwsz + 1);
    *lpw++ = 0;

    lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3);

    // OK button
    lpdit = (LPDLGITEMTEMPLATE)lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP;
    lpdit->x = 30;
    lpdit->y = 55;
    lpdit->cx = 60;
    lpdit->cy = 20;
    lpdit->id = IDC_OK_BUTTON;

    lpw = (LPWORD)(lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0080;

    lpwsz = (LPWSTR)lpw;
    wcscpy_s(lpwsz, 10, L"OK");
    lpw = (LPWORD)(lpwsz + wcslen(lpwsz) + 1);
    *lpw++ = 0;

    lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3);

    // Cancel button
    lpdit = (LPDLGITEMTEMPLATE)lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP;
    lpdit->x = 110;
    lpdit->y = 55;
    lpdit->cx = 60;
    lpdit->cy = 20;
    lpdit->id = IDC_CANCEL_BUTTON;

    lpw = (LPWORD)(lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0080;

    lpwsz = (LPWSTR)lpw;
    wcscpy_s(lpwsz, 10, L"Cancel");
    lpw = (LPWORD)(lpwsz + wcslen(lpwsz) + 1);
    *lpw++ = 0;

    GlobalUnlock(hgbl);

    DialogBoxIndirectW(NULL, (LPDLGTEMPLATE)hgbl, parent, OTPInputDlgProc);

    GlobalFree(hgbl);

    return g_otpResult;
}

HWND AuthDialog::ShowPushWaitingDialog(HWND parent) {
    // Create a simple popup window for waiting
    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        L"STATIC",
        L"Waiting for push approval...\n\nPlease check your phone.",
        WS_POPUP | WS_VISIBLE | WS_BORDER | SS_CENTER,
        (GetSystemMetrics(SM_CXSCREEN) - 300) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - 100) / 2,
        300, 100,
        parent, NULL, NULL, NULL
    );

    if (hwnd) {
        // Set font
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, TRUE);
        UpdateWindow(hwnd);
    }

    return hwnd;
}

void AuthDialog::ClosePushWaitingDialog(HWND hwnd) {
    if (hwnd && IsWindow(hwnd)) {
        DestroyWindow(hwnd);
    }
}

void AuthDialog::ShowPushResultDialog(HWND parent, PushResult result) {
    const wchar_t* title = L"WorldPosta Authentication";
    const wchar_t* message;
    UINT type;

    switch (result) {
    case PushResult::APPROVED:
        message = L"Push notification approved!";
        type = MB_OK | MB_ICONINFORMATION;
        break;
    case PushResult::DENIED:
        message = L"Push notification was denied.";
        type = MB_OK | MB_ICONWARNING;
        break;
    case PushResult::TIMEOUT:
        message = L"Push notification timed out.\nPlease try again.";
        type = MB_OK | MB_ICONWARNING;
        break;
    default:
        message = L"An error occurred.\nPlease try again.";
        type = MB_OK | MB_ICONERROR;
        break;
    }

    MessageBoxW(parent, message, title, type);
}
