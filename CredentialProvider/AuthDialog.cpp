#include "AuthDialog.h"
#include <CommCtrl.h>
#include <windowsx.h>
#include <gdiplus.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdiplus.lib")

// WorldPosta brand colors
#define WP_GREEN RGB(103, 154, 65)      // #679a41
#define WP_DARK_BLUE RGB(41, 60, 81)    // #293c51
#define WP_WHITE RGB(255, 255, 255)
#define WP_LIGHT_GRAY RGB(245, 245, 245)
#define WP_BORDER_GRAY RGB(220, 220, 220)

// Dialog dimensions (Duo-like)
#define DLG_WIDTH 700
#define DLG_HEIGHT 450
#define LEFT_PANEL_WIDTH 220
#define FOOTER_HEIGHT 60
#define LOGO_CIRCLE_SIZE 150

// Dialog control IDs
#define IDC_OTP_EDIT 1001
#define IDC_OK_BUTTON 1002
#define IDC_CANCEL_BUTTON 1003
#define IDC_PUSH_BUTTON 1004
#define IDC_OTP_BUTTON 1005
#define IDC_WAITING_TEXT 1006
#define IDC_LOGO_STATIC 1007
#define IDC_TITLE_STATIC 1008
#define IDC_STATUS_STATIC 1009

// Global to store OTP result
static std::wstring g_otpResult;
static AuthMethod g_authChoice = AuthMethod::CANCEL;

// GDI+ token
static ULONG_PTR g_gdiplusToken = 0;

// Custom window class name
static const wchar_t* WP_DIALOG_CLASS = L"WorldPostaAuthDialog";
static bool g_classRegistered = false;

// Initialize GDI+
static void InitGDIPlus() {
    if (g_gdiplusToken == 0) {
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);
    }
}

// Draw rounded rectangle
static void DrawRoundedRect(HDC hdc, RECT* rect, int radius, COLORREF fillColor, COLORREF borderColor) {
    HBRUSH hBrush = CreateSolidBrush(fillColor);
    HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
    HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, hBrush);
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);

    RoundRect(hdc, rect->left, rect->top, rect->right, rect->bottom, radius, radius);

    SelectObject(hdc, hOldBrush);
    SelectObject(hdc, hOldPen);
    DeleteObject(hBrush);
    DeleteObject(hPen);
}

// Draw the WorldPosta logo (simplified - C with arrow)
static void DrawWorldPostaLogo(HDC hdc, int centerX, int centerY, int size) {
    using namespace Gdiplus;

    Graphics graphics(hdc);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);

    // Draw green circle background
    SolidBrush greenBrush(Color(255, 103, 154, 65));
    graphics.FillEllipse(&greenBrush,
        centerX - size/2, centerY - size/2, size, size);

    // Draw the "C" shape (dark blue)
    int cSize = (int)(size * 0.6);
    int cThickness = (int)(size * 0.12);
    int cX = centerX - cSize/2 - (int)(size * 0.05);
    int cY = centerY - cSize/2;

    Pen bluePen(Color(255, 41, 60, 81), (float)cThickness);
    bluePen.SetStartCap(LineCapRound);
    bluePen.SetEndCap(LineCapRound);

    // Draw C as an arc
    graphics.DrawArc(&bluePen, cX, cY, cSize, cSize, 45, 270);

    // Draw the arrow (green)
    int arrowSize = (int)(size * 0.35);
    int arrowX = centerX + (int)(size * 0.05);
    int arrowY = centerY;

    SolidBrush arrowBrush(Color(255, 103, 154, 65));

    // Arrow pointing left (triangle)
    Point arrowPoints[3] = {
        Point(arrowX - arrowSize/2, arrowY),
        Point(arrowX + arrowSize/3, arrowY - arrowSize/2),
        Point(arrowX + arrowSize/3, arrowY + arrowSize/2)
    };

    // Actually draw as white on green circle
    SolidBrush whiteBrush(Color(255, 255, 255, 255));
    graphics.FillPolygon(&whiteBrush, arrowPoints, 3);

    // Arrow stem
    int stemWidth = (int)(arrowSize * 0.4);
    int stemLength = (int)(arrowSize * 0.6);
    graphics.FillRectangle(&whiteBrush,
        arrowX + arrowSize/3 - stemLength, arrowY - stemWidth/2,
        stemLength, stemWidth);
}

// Draw auth option button
static void DrawAuthOptionButton(HDC hdc, RECT* rect, const wchar_t* title, const wchar_t* icon, bool hover) {
    // Draw button background
    COLORREF bgColor = hover ? WP_LIGHT_GRAY : WP_WHITE;
    DrawRoundedRect(hdc, rect, 8, bgColor, WP_BORDER_GRAY);

    // Draw icon placeholder (circle)
    int iconSize = 40;
    int iconX = rect->left + 20;
    int iconY = rect->top + (rect->bottom - rect->top - iconSize) / 2;

    HBRUSH iconBrush = CreateSolidBrush(WP_LIGHT_GRAY);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, iconBrush);
    Ellipse(hdc, iconX, iconY, iconX + iconSize, iconY + iconSize);
    SelectObject(hdc, oldBrush);
    DeleteObject(iconBrush);

    // Draw title text
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, WP_DARK_BLUE);

    HFONT hFont = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    HFONT oldFont = (HFONT)SelectObject(hdc, hFont);

    RECT textRect = {iconX + iconSize + 15, rect->top, rect->right - 20, rect->bottom};
    DrawTextW(hdc, title, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, oldFont);
    DeleteObject(hFont);
}

// Main dialog window procedure
static LRESULT CALLBACK AuthDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static int hoveredButton = 0;
    static RECT pushButtonRect = {0};
    static RECT otpButtonRect = {0};
    static RECT cancelButtonRect = {0};

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();

            // Calculate button positions
            int rightPanelX = LEFT_PANEL_WIDTH;
            int rightPanelWidth = DLG_WIDTH - LEFT_PANEL_WIDTH;
            int buttonWidth = rightPanelWidth - 80;
            int buttonHeight = 70;
            int startY = 100;
            int spacing = 20;

            pushButtonRect = {rightPanelX + 40, startY, rightPanelX + 40 + buttonWidth, startY + buttonHeight};
            otpButtonRect = {rightPanelX + 40, startY + buttonHeight + spacing,
                            rightPanelX + 40 + buttonWidth, startY + buttonHeight * 2 + spacing};

            // Cancel button in footer
            cancelButtonRect = {DLG_WIDTH - 150, DLG_HEIGHT - FOOTER_HEIGHT + 15,
                               DLG_WIDTH - 30, DLG_HEIGHT - 15};
        }
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            // Create memory DC for double buffering
            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, DLG_WIDTH, DLG_HEIGHT);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            // Fill background white
            RECT clientRect = {0, 0, DLG_WIDTH, DLG_HEIGHT};
            HBRUSH whiteBrush = CreateSolidBrush(WP_WHITE);
            FillRect(memDC, &clientRect, whiteBrush);
            DeleteObject(whiteBrush);

            // Draw left panel (white with logo)
            RECT leftPanel = {0, 0, LEFT_PANEL_WIDTH, DLG_HEIGHT - FOOTER_HEIGHT};
            HBRUSH leftBrush = CreateSolidBrush(WP_WHITE);
            FillRect(memDC, &leftPanel, leftBrush);
            DeleteObject(leftBrush);

            // Draw logo in center of left panel
            int logoCenterX = LEFT_PANEL_WIDTH / 2;
            int logoCenterY = (DLG_HEIGHT - FOOTER_HEIGHT) / 2 - 30;
            DrawWorldPostaLogo(memDC, logoCenterX, logoCenterY, LOGO_CIRCLE_SIZE);

            // Draw "Powered by WorldPosta" text
            SetBkMode(memDC, TRANSPARENT);
            SetTextColor(memDC, WP_DARK_BLUE);

            HFONT smallFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, smallFont);

            RECT poweredRect = {0, logoCenterY + LOGO_CIRCLE_SIZE/2 + 20, LEFT_PANEL_WIDTH,
                               logoCenterY + LOGO_CIRCLE_SIZE/2 + 50};
            DrawTextW(memDC, L"Powered by WorldPosta", -1, &poweredRect, DT_CENTER | DT_SINGLELINE);

            SelectObject(memDC, oldFont);
            DeleteObject(smallFont);

            // Draw right panel header
            SetTextColor(memDC, WP_DARK_BLUE);
            HFONT titleFont = CreateFontW(20, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, titleFont);

            RECT titleRect = {LEFT_PANEL_WIDTH + 40, 40, DLG_WIDTH - 40, 80};
            DrawTextW(memDC, L"Choose an authentication method", -1, &titleRect, DT_LEFT | DT_SINGLELINE);

            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);

            // Draw auth option buttons
            DrawAuthOptionButton(memDC, &pushButtonRect, L"WorldPosta Push", L"phone", hoveredButton == 1);
            DrawAuthOptionButton(memDC, &otpButtonRect, L"Enter Passcode", L"keypad", hoveredButton == 2);

            // Draw footer bar
            RECT footerRect = {0, DLG_HEIGHT - FOOTER_HEIGHT, DLG_WIDTH, DLG_HEIGHT};
            HBRUSH footerBrush = CreateSolidBrush(WP_DARK_BLUE);
            FillRect(memDC, &footerRect, footerBrush);
            DeleteObject(footerBrush);

            // Draw cancel button in footer
            DrawRoundedRect(memDC, &cancelButtonRect, 5, WP_WHITE, WP_WHITE);
            SetTextColor(memDC, WP_DARK_BLUE);
            HFONT btnFont = CreateFontW(14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, btnFont);
            DrawTextW(memDC, L"Cancel", -1, &cancelButtonRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(btnFont);

            // Copy to screen
            BitBlt(hdc, 0, 0, DLG_WIDTH, DLG_HEIGHT, memDC, 0, 0, SRCCOPY);

            // Cleanup
            SelectObject(memDC, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDC);

            EndPaint(hwnd, &ps);
        }
        return 0;

    case WM_MOUSEMOVE:
        {
            int x = GET_X_LPARAM(lParam);
            int y = GET_Y_LPARAM(lParam);

            int newHover = 0;
            if (PtInRect(&pushButtonRect, {x, y})) newHover = 1;
            else if (PtInRect(&otpButtonRect, {x, y})) newHover = 2;

            if (newHover != hoveredButton) {
                hoveredButton = newHover;
                InvalidateRect(hwnd, NULL, FALSE);
            }

            // Set cursor
            SetCursor(LoadCursor(NULL, newHover ? IDC_HAND : IDC_ARROW));
        }
        return 0;

    case WM_LBUTTONDOWN:
        {
            int x = GET_X_LPARAM(lParam);
            int y = GET_Y_LPARAM(lParam);

            if (PtInRect(&pushButtonRect, {x, y})) {
                g_authChoice = AuthMethod::PUSH;
                DestroyWindow(hwnd);
            } else if (PtInRect(&otpButtonRect, {x, y})) {
                g_authChoice = AuthMethod::OTP;
                DestroyWindow(hwnd);
            } else if (PtInRect(&cancelButtonRect, {x, y})) {
                g_authChoice = AuthMethod::CANCEL;
                DestroyWindow(hwnd);
            }
        }
        return 0;

    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE) {
            g_authChoice = AuthMethod::CANCEL;
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_CLOSE:
        g_authChoice = AuthMethod::CANCEL;
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// Register window class
static void RegisterAuthDialogClass(HINSTANCE hInstance) {
    if (g_classRegistered) return;

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = AuthDialogWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = WP_DIALOG_CLASS;

    RegisterClassExW(&wc);
    g_classRegistered = true;
}

// Show auth choice dialog (Duo-like)
AuthMethod AuthDialog::ShowAuthChoiceDialog(HWND parent) {
    g_authChoice = AuthMethod::CANCEL;

    HINSTANCE hInstance = GetModuleHandle(NULL);
    RegisterAuthDialogClass(hInstance);

    // Calculate center position
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenWidth - DLG_WIDTH) / 2;
    int y = (screenHeight - DLG_HEIGHT) / 2;

    // Create the window
    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        WP_DIALOG_CLASS,
        L"WorldPosta Authentication",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        x, y, DLG_WIDTH, DLG_HEIGHT,
        parent,
        NULL,
        hInstance,
        NULL
    );

    if (!hwnd) return AuthMethod::CANCEL;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return g_authChoice;
}

// OTP Input Dialog - also modernized
static LRESULT CALLBACK OTPDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit = NULL;
    static RECT okButtonRect = {0};
    static RECT cancelButtonRect = {0};
    static int hoveredButton = 0;

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();

            // Create edit control
            hEdit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER | ES_NUMBER,
                LEFT_PANEL_WIDTH + 40, 140,
                DLG_WIDTH - LEFT_PANEL_WIDTH - 80, 40,
                hwnd, (HMENU)IDC_OTP_EDIT, NULL, NULL
            );

            // Set font for edit
            HFONT editFont = CreateFontW(24, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SendMessage(hEdit, WM_SETFONT, (WPARAM)editFont, TRUE);
            SetFocus(hEdit);

            // Calculate button positions
            int btnWidth = 100;
            int btnHeight = 40;
            int btnY = 210;
            int centerX = LEFT_PANEL_WIDTH + (DLG_WIDTH - LEFT_PANEL_WIDTH) / 2;

            okButtonRect = {centerX - btnWidth - 10, btnY, centerX - 10, btnY + btnHeight};
            cancelButtonRect = {centerX + 10, btnY, centerX + btnWidth + 10, btnY + btnHeight};
        }
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            // Create memory DC
            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, DLG_WIDTH, 320);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            // Fill background
            RECT clientRect = {0, 0, DLG_WIDTH, 320};
            HBRUSH whiteBrush = CreateSolidBrush(WP_WHITE);
            FillRect(memDC, &clientRect, whiteBrush);
            DeleteObject(whiteBrush);

            // Draw logo in left panel
            int logoCenterX = LEFT_PANEL_WIDTH / 2;
            int logoCenterY = 130;
            DrawWorldPostaLogo(memDC, logoCenterX, logoCenterY, 120);

            // "Powered by" text
            SetBkMode(memDC, TRANSPARENT);
            SetTextColor(memDC, WP_DARK_BLUE);
            HFONT smallFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, smallFont);
            RECT poweredRect = {0, 210, LEFT_PANEL_WIDTH, 240};
            DrawTextW(memDC, L"Powered by WorldPosta", -1, &poweredRect, DT_CENTER | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(smallFont);

            // Title
            HFONT titleFont = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, titleFont);
            RECT titleRect = {LEFT_PANEL_WIDTH + 40, 50, DLG_WIDTH - 40, 90};
            DrawTextW(memDC, L"Enter your passcode", -1, &titleRect, DT_LEFT | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);

            // Instruction text
            HFONT instrFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, instrFont);
            SetTextColor(memDC, RGB(100, 100, 100));
            RECT instrRect = {LEFT_PANEL_WIDTH + 40, 100, DLG_WIDTH - 40, 130};
            DrawTextW(memDC, L"Enter the code from your WorldPosta app", -1, &instrRect, DT_LEFT | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(instrFont);

            // OK button (green)
            HBRUSH okBrush = CreateSolidBrush(WP_GREEN);
            HBRUSH oldBrush = (HBRUSH)SelectObject(memDC, okBrush);
            HPEN okPen = CreatePen(PS_SOLID, 1, WP_GREEN);
            HPEN oldPen = (HPEN)SelectObject(memDC, okPen);
            RoundRect(memDC, okButtonRect.left, okButtonRect.top,
                     okButtonRect.right, okButtonRect.bottom, 8, 8);
            SelectObject(memDC, oldBrush);
            SelectObject(memDC, oldPen);
            DeleteObject(okBrush);
            DeleteObject(okPen);

            SetTextColor(memDC, WP_WHITE);
            HFONT btnFont = CreateFontW(14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, btnFont);
            DrawTextW(memDC, L"Verify", -1, &okButtonRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            // Cancel button (outline)
            HBRUSH cancelBrush = CreateSolidBrush(WP_WHITE);
            oldBrush = (HBRUSH)SelectObject(memDC, cancelBrush);
            HPEN cancelPen = CreatePen(PS_SOLID, 2, WP_DARK_BLUE);
            oldPen = (HPEN)SelectObject(memDC, cancelPen);
            RoundRect(memDC, cancelButtonRect.left, cancelButtonRect.top,
                     cancelButtonRect.right, cancelButtonRect.bottom, 8, 8);
            SelectObject(memDC, oldBrush);
            SelectObject(memDC, oldPen);
            DeleteObject(cancelBrush);
            DeleteObject(cancelPen);

            SetTextColor(memDC, WP_DARK_BLUE);
            DrawTextW(memDC, L"Cancel", -1, &cancelButtonRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(memDC, oldFont);
            DeleteObject(btnFont);

            // Copy to screen
            BitBlt(hdc, 0, 0, DLG_WIDTH, 320, memDC, 0, 0, SRCCOPY);

            SelectObject(memDC, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDC);

            EndPaint(hwnd, &ps);
        }
        return 0;

    case WM_LBUTTONDOWN:
        {
            int x = GET_X_LPARAM(lParam);
            int y = GET_Y_LPARAM(lParam);

            if (PtInRect(&okButtonRect, {x, y})) {
                wchar_t buffer[64] = {0};
                GetWindowTextW(hEdit, buffer, 64);
                g_otpResult = buffer;
                DestroyWindow(hwnd);
            } else if (PtInRect(&cancelButtonRect, {x, y})) {
                g_otpResult = L"";
                DestroyWindow(hwnd);
            }
        }
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_OTP_EDIT && HIWORD(wParam) == EN_CHANGE) {
            // Could add real-time validation here
        }
        return 0;

    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            wchar_t buffer[64] = {0};
            GetWindowTextW(hEdit, buffer, 64);
            g_otpResult = buffer;
            DestroyWindow(hwnd);
        } else if (wParam == VK_ESCAPE) {
            g_otpResult = L"";
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_CLOSE:
        g_otpResult = L"";
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static const wchar_t* WP_OTP_DIALOG_CLASS = L"WorldPostaOTPDialog";
static bool g_otpClassRegistered = false;

static void RegisterOTPDialogClass(HINSTANCE hInstance) {
    if (g_otpClassRegistered) return;

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = OTPDialogWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = WP_OTP_DIALOG_CLASS;

    RegisterClassExW(&wc);
    g_otpClassRegistered = true;
}

std::wstring AuthDialog::ShowOTPInputDialog(HWND parent) {
    g_otpResult = L"";

    HINSTANCE hInstance = GetModuleHandle(NULL);
    RegisterOTPDialogClass(hInstance);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int dlgWidth = DLG_WIDTH;
    int dlgHeight = 320;
    int x = (screenWidth - dlgWidth) / 2;
    int y = (screenHeight - dlgHeight) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        WP_OTP_DIALOG_CLASS,
        L"Enter Passcode",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        x, y, dlgWidth, dlgHeight,
        parent,
        NULL,
        hInstance,
        NULL
    );

    if (!hwnd) return L"";

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return g_otpResult;
}

// Push waiting dialog - modern style
static LRESULT CALLBACK PushWaitingWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static RECT cancelButtonRect = {0};

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();
            cancelButtonRect = {DLG_WIDTH - 150, 200, DLG_WIDTH - 30, 240};
        }
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, DLG_WIDTH, 280);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            // Background
            RECT clientRect = {0, 0, DLG_WIDTH, 280};
            HBRUSH whiteBrush = CreateSolidBrush(WP_WHITE);
            FillRect(memDC, &clientRect, whiteBrush);
            DeleteObject(whiteBrush);

            // Logo
            DrawWorldPostaLogo(memDC, LEFT_PANEL_WIDTH / 2, 110, 120);

            // "Powered by" text
            SetBkMode(memDC, TRANSPARENT);
            SetTextColor(memDC, WP_DARK_BLUE);
            HFONT smallFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, smallFont);
            RECT poweredRect = {0, 190, LEFT_PANEL_WIDTH, 220};
            DrawTextW(memDC, L"Powered by WorldPosta", -1, &poweredRect, DT_CENTER | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(smallFont);

            // Status text
            HFONT titleFont = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, titleFont);
            RECT titleRect = {LEFT_PANEL_WIDTH + 40, 80, DLG_WIDTH - 40, 120};
            DrawTextW(memDC, L"Push notification sent", -1, &titleRect, DT_LEFT | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);

            // Instruction
            HFONT instrFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, instrFont);
            SetTextColor(memDC, RGB(100, 100, 100));
            RECT instrRect = {LEFT_PANEL_WIDTH + 40, 130, DLG_WIDTH - 40, 180};
            DrawTextW(memDC, L"Please check your phone and approve\nthe authentication request.", -1, &instrRect, DT_LEFT);
            SelectObject(memDC, oldFont);
            DeleteObject(instrFont);

            // Cancel button
            HBRUSH btnBrush = CreateSolidBrush(WP_WHITE);
            HBRUSH oldBrush = (HBRUSH)SelectObject(memDC, btnBrush);
            HPEN btnPen = CreatePen(PS_SOLID, 2, WP_DARK_BLUE);
            HPEN oldPen = (HPEN)SelectObject(memDC, btnPen);
            RoundRect(memDC, cancelButtonRect.left, cancelButtonRect.top,
                     cancelButtonRect.right, cancelButtonRect.bottom, 8, 8);
            SelectObject(memDC, oldBrush);
            SelectObject(memDC, oldPen);
            DeleteObject(btnBrush);
            DeleteObject(btnPen);

            SetTextColor(memDC, WP_DARK_BLUE);
            HFONT btnFont = CreateFontW(14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, btnFont);
            DrawTextW(memDC, L"Cancel", -1, &cancelButtonRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(btnFont);

            BitBlt(hdc, 0, 0, DLG_WIDTH, 280, memDC, 0, 0, SRCCOPY);

            SelectObject(memDC, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDC);

            EndPaint(hwnd, &ps);
        }
        return 0;

    case WM_LBUTTONDOWN:
        {
            int x = GET_X_LPARAM(lParam);
            int y = GET_Y_LPARAM(lParam);
            if (PtInRect(&cancelButtonRect, {x, y})) {
                DestroyWindow(hwnd);
            }
        }
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static const wchar_t* WP_PUSH_WAITING_CLASS = L"WorldPostaPushWaiting";
static bool g_pushWaitingClassRegistered = false;

HWND AuthDialog::ShowPushWaitingDialog(HWND parent) {
    if (!g_pushWaitingClassRegistered) {
        WNDCLASSEXW wc = {0};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = PushWaitingWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = WP_PUSH_WAITING_CLASS;
        RegisterClassExW(&wc);
        g_pushWaitingClassRegistered = true;
    }

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenWidth - DLG_WIDTH) / 2;
    int y = (screenHeight - 280) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        WP_PUSH_WAITING_CLASS,
        L"WorldPosta Authentication",
        WS_POPUP | WS_CAPTION | WS_VISIBLE,
        x, y, DLG_WIDTH, 280,
        parent,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );

    if (hwnd) {
        ShowWindow(hwnd, SW_SHOW);
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
        message = L"Authentication approved!";
        type = MB_OK | MB_ICONINFORMATION;
        break;
    case PushResult::DENIED:
        message = L"Authentication was denied.";
        type = MB_OK | MB_ICONWARNING;
        break;
    case PushResult::TIMEOUT:
        message = L"Authentication request timed out.\nPlease try again.";
        type = MB_OK | MB_ICONWARNING;
        break;
    default:
        message = L"An error occurred.\nPlease try again.";
        type = MB_OK | MB_ICONERROR;
        break;
    }

    MessageBoxW(parent, message, title, type);
}
