#include "AuthDialog.h"
#include <CommCtrl.h>
#include <windowsx.h>
#include <gdiplus.h>
#include <shlobj.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdiplus.lib")

// WorldPosta brand colors
#define WP_GREEN RGB(103, 154, 65)      // #679a41
#define WP_DARK_BLUE RGB(41, 60, 81)    // #293c51
#define WP_WHITE RGB(255, 255, 255)
#define WP_LIGHT_GRAY RGB(245, 245, 245)
#define WP_BORDER_GRAY RGB(220, 220, 220)

// Dialog dimensions (Duo-like) - increased height for footer
#define DLG_WIDTH 720
#define DLG_HEIGHT 500
#define LEFT_PANEL_WIDTH 230
#define FOOTER_HEIGHT 70
#define LOGO_SIZE 150

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

// GDI+ token and logo images
static ULONG_PTR g_gdiplusToken = 0;
static Gdiplus::Image* g_logoImage = nullptr;
static Gdiplus::Image* g_smallIconImage = nullptr;

// Custom window class names
static const wchar_t* WP_DIALOG_CLASS = L"WorldPostaAuthDialog";
static const wchar_t* WP_OTP_DIALOG_CLASS = L"WorldPostaOTPDialog";
static const wchar_t* WP_PUSH_WAITING_CLASS = L"WorldPostaPushWaiting";
static bool g_classRegistered = false;
static bool g_otpClassRegistered = false;
static bool g_pushWaitingClassRegistered = false;

// Initialize GDI+
static void InitGDIPlus() {
    if (g_gdiplusToken == 0) {
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);
    }
}

// Load logo images from installed path
static void LoadLogoImage() {
    InitGDIPlus();

    wchar_t basePath[MAX_PATH];

    // Get Program Files path
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, basePath))) {
        // Load main logo if not already loaded
        if (g_logoImage == nullptr) {
            wchar_t logoPath[MAX_PATH];
            wcscpy_s(logoPath, basePath);
            wcscat_s(logoPath, L"\\multiOTP\\loginLogo.bmp");
            g_logoImage = Gdiplus::Image::FromFile(logoPath);
            if (g_logoImage && g_logoImage->GetLastStatus() != Gdiplus::Ok) {
                delete g_logoImage;
                g_logoImage = nullptr;
            }
        }

        // Load small icon if not already loaded
        if (g_smallIconImage == nullptr) {
            wchar_t iconPath[MAX_PATH];
            wcscpy_s(iconPath, basePath);
            wcscat_s(iconPath, L"\\multiOTP\\smallIcon.bmp");
            g_smallIconImage = Gdiplus::Image::FromFile(iconPath);
            if (g_smallIconImage && g_smallIconImage->GetLastStatus() != Gdiplus::Ok) {
                delete g_smallIconImage;
                g_smallIconImage = nullptr;
            }
        }
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

// Draw the WorldPosta logo (loads actual logo image)
static void DrawWorldPostaLogo(HDC hdc, int centerX, int centerY, int size) {
    using namespace Gdiplus;

    Graphics graphics(hdc);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);

    // Load and draw the actual logo (no green circle - logo file already has proper design)
    LoadLogoImage();

    if (g_logoImage != nullptr) {
        // Draw the logo centered at the specified position
        int logoX = centerX - size / 2;
        int logoY = centerY - size / 2;
        graphics.DrawImage(g_logoImage, logoX, logoY, size, size);
    }
}

// Draw auth option button (card style like Duo)
static void DrawAuthOptionButton(HDC hdc, RECT* rect, const wchar_t* title, const wchar_t* subtitle, bool hover) {
    using namespace Gdiplus;

    Graphics graphics(hdc);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);

    // Button background
    Color bgColor = hover ? Color(255, 245, 245, 245) : Color(255, 255, 255, 255);
    Color borderColor(255, 220, 220, 220);

    // Draw rounded rectangle
    GraphicsPath path;
    int radius = 8;
    path.AddArc(rect->left, rect->top, radius*2, radius*2, 180, 90);
    path.AddArc(rect->right - radius*2, rect->top, radius*2, radius*2, 270, 90);
    path.AddArc(rect->right - radius*2, rect->bottom - radius*2, radius*2, radius*2, 0, 90);
    path.AddArc(rect->left, rect->bottom - radius*2, radius*2, radius*2, 90, 90);
    path.CloseFigure();

    SolidBrush fillBrush(bgColor);
    graphics.FillPath(&fillBrush, &path);

    Pen borderPen(borderColor, 1);
    graphics.DrawPath(&borderPen, &path);

    // Icon on left - draw the small icon with logo
    int iconSize = 45;
    int iconX = rect->left + 20;
    int iconY = rect->top + (rect->bottom - rect->top - iconSize) / 2;

    // Load images if needed
    LoadLogoImage();

    if (g_smallIconImage != nullptr) {
        // Draw the small icon (logo in green circle)
        graphics.DrawImage(g_smallIconImage, iconX, iconY, iconSize, iconSize);
    } else {
        // Fallback: draw green circle if image not loaded
        SolidBrush iconBrush(Color(255, 103, 154, 65));
        graphics.FillEllipse(&iconBrush, iconX, iconY, iconSize, iconSize);
    }

    // Title text
    FontFamily fontFamily(L"Segoe UI");
    Font titleFont(&fontFamily, 16, FontStyleBold, UnitPixel);
    Font subtitleFont(&fontFamily, 12, FontStyleRegular, UnitPixel);

    SolidBrush textBrush(Color(255, 41, 60, 81));
    SolidBrush subtitleBrush(Color(255, 128, 128, 128));

    PointF titlePos((float)(iconX + iconSize + 18), (float)(rect->top + 18));
    PointF subtitlePos((float)(iconX + iconSize + 18), (float)(rect->top + 42));

    graphics.DrawString(title, -1, &titleFont, titlePos, &textBrush);
    graphics.DrawString(subtitle, -1, &subtitleFont, subtitlePos, &subtitleBrush);

    // Right arrow or action button
    int btnWidth = 100;
    int btnHeight = 35;
    int btnX = rect->right - btnWidth - 20;
    int btnY = rect->top + (rect->bottom - rect->top - btnHeight) / 2;

    SolidBrush btnBrush(Color(255, 220, 220, 220));
    RectF btnRect((float)btnX, (float)btnY, (float)btnWidth, (float)btnHeight);

    GraphicsPath btnPath;
    btnPath.AddArc(btnX, btnY, 6, 6, 180, 90);
    btnPath.AddArc(btnX + btnWidth - 6, btnY, 6, 6, 270, 90);
    btnPath.AddArc(btnX + btnWidth - 6, btnY + btnHeight - 6, 6, 6, 0, 90);
    btnPath.AddArc(btnX, btnY + btnHeight - 6, 6, 6, 90, 90);
    btnPath.CloseFigure();
    graphics.FillPath(&btnBrush, &btnPath);

    // Button text
    Font btnFont(&fontFamily, 12, FontStyleRegular, UnitPixel);
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);
    graphics.DrawString(hover ? L"Select" : L"Select", -1, &btnFont, btnRect, &sf, &textBrush);
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
            LoadLogoImage();

            // Calculate button positions
            int rightPanelX = LEFT_PANEL_WIDTH;
            int rightPanelWidth = DLG_WIDTH - LEFT_PANEL_WIDTH;
            int buttonWidth = rightPanelWidth - 80;
            int buttonHeight = 80;
            int startY = 120;
            int spacing = 25;

            pushButtonRect = {rightPanelX + 40, startY, rightPanelX + 40 + buttonWidth, startY + buttonHeight};
            otpButtonRect = {rightPanelX + 40, startY + buttonHeight + spacing,
                            rightPanelX + 40 + buttonWidth, startY + buttonHeight * 2 + spacing};

            // Cancel button in footer
            cancelButtonRect = {DLG_WIDTH - 140, DLG_HEIGHT - FOOTER_HEIGHT + 18,
                               DLG_WIDTH - 20, DLG_HEIGHT - 18};
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

            // Draw left panel background (light gray)
            RECT leftPanel = {0, 0, LEFT_PANEL_WIDTH, DLG_HEIGHT - FOOTER_HEIGHT};
            HBRUSH leftBrush = CreateSolidBrush(RGB(250, 250, 250));
            FillRect(memDC, &leftPanel, leftBrush);
            DeleteObject(leftBrush);

            // Draw logo in center of left panel
            int logoCenterX = LEFT_PANEL_WIDTH / 2;
            int logoCenterY = (DLG_HEIGHT - FOOTER_HEIGHT) / 2 - 20;
            DrawWorldPostaLogo(memDC, logoCenterX, logoCenterY, LOGO_SIZE);

            // Draw "Powered by WorldPosta" text
            SetBkMode(memDC, TRANSPARENT);
            SetTextColor(memDC, WP_DARK_BLUE);

            HFONT smallFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, smallFont);

            RECT poweredRect = {0, logoCenterY + LOGO_SIZE/2 + 25, LEFT_PANEL_WIDTH,
                               logoCenterY + LOGO_SIZE/2 + 55};
            DrawTextW(memDC, L"Powered by WorldPosta", -1, &poweredRect, DT_CENTER | DT_SINGLELINE);

            SelectObject(memDC, oldFont);
            DeleteObject(smallFont);

            // Draw right panel header
            SetTextColor(memDC, WP_DARK_BLUE);
            HFONT titleFont = CreateFontW(22, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, titleFont);

            RECT titleRect = {LEFT_PANEL_WIDTH + 40, 50, DLG_WIDTH - 40, 90};
            DrawTextW(memDC, L"Choose an authentication method", -1, &titleRect, DT_LEFT | DT_SINGLELINE);

            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);

            // Draw auth option buttons
            DrawAuthOptionButton(memDC, &pushButtonRect, L"WorldPosta Push", L"Send notification to your phone", hoveredButton == 1);
            DrawAuthOptionButton(memDC, &otpButtonRect, L"Enter Passcode", L"Enter code from your app", hoveredButton == 2);

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
            POINT pt = {x, y};
            if (PtInRect(&pushButtonRect, pt)) newHover = 1;
            else if (PtInRect(&otpButtonRect, pt)) newHover = 2;

            if (newHover != hoveredButton) {
                hoveredButton = newHover;
                InvalidateRect(hwnd, NULL, FALSE);
            }

            SetCursor(LoadCursor(NULL, newHover ? IDC_HAND : IDC_ARROW));
        }
        return 0;

    case WM_LBUTTONDOWN:
        {
            int x = GET_X_LPARAM(lParam);
            int y = GET_Y_LPARAM(lParam);
            POINT pt = {x, y};

            if (PtInRect(&pushButtonRect, pt)) {
                g_authChoice = AuthMethod::PUSH;
                DestroyWindow(hwnd);
            } else if (PtInRect(&otpButtonRect, pt)) {
                g_authChoice = AuthMethod::OTP;
                DestroyWindow(hwnd);
            } else if (PtInRect(&cancelButtonRect, pt)) {
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

// OTP Input Dialog
static LRESULT CALLBACK OTPDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit = NULL;
    static RECT okButtonRect = {0};
    static RECT cancelButtonRect = {0};

    const int OTP_DLG_WIDTH = 720;
    const int OTP_DLG_HEIGHT = 350;

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();
            LoadLogoImage();

            // Create edit control
            hEdit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER | ES_NUMBER,
                LEFT_PANEL_WIDTH + 40, 160,
                OTP_DLG_WIDTH - LEFT_PANEL_WIDTH - 80, 45,
                hwnd, (HMENU)IDC_OTP_EDIT, NULL, NULL
            );

            HFONT editFont = CreateFontW(28, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SendMessage(hEdit, WM_SETFONT, (WPARAM)editFont, TRUE);
            SetFocus(hEdit);

            int btnWidth = 110;
            int btnHeight = 42;
            int btnY = 230;
            int centerX = LEFT_PANEL_WIDTH + (OTP_DLG_WIDTH - LEFT_PANEL_WIDTH) / 2;

            okButtonRect = {centerX - btnWidth - 15, btnY, centerX - 15, btnY + btnHeight};
            cancelButtonRect = {centerX + 15, btnY, centerX + btnWidth + 15, btnY + btnHeight};
        }
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, OTP_DLG_WIDTH, OTP_DLG_HEIGHT);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            // Background
            RECT clientRect = {0, 0, OTP_DLG_WIDTH, OTP_DLG_HEIGHT};
            HBRUSH whiteBrush = CreateSolidBrush(WP_WHITE);
            FillRect(memDC, &clientRect, whiteBrush);
            DeleteObject(whiteBrush);

            // Left panel
            RECT leftPanel = {0, 0, LEFT_PANEL_WIDTH, OTP_DLG_HEIGHT};
            HBRUSH leftBrush = CreateSolidBrush(RGB(250, 250, 250));
            FillRect(memDC, &leftPanel, leftBrush);
            DeleteObject(leftBrush);

            // Logo
            DrawWorldPostaLogo(memDC, LEFT_PANEL_WIDTH / 2, OTP_DLG_HEIGHT / 2 - 30, 130);

            // "Powered by" text
            SetBkMode(memDC, TRANSPARENT);
            SetTextColor(memDC, WP_DARK_BLUE);
            HFONT smallFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, smallFont);
            RECT poweredRect = {0, OTP_DLG_HEIGHT / 2 + 50, LEFT_PANEL_WIDTH, OTP_DLG_HEIGHT / 2 + 80};
            DrawTextW(memDC, L"Powered by WorldPosta", -1, &poweredRect, DT_CENTER | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(smallFont);

            // Title
            HFONT titleFont = CreateFontW(22, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, titleFont);
            RECT titleRect = {LEFT_PANEL_WIDTH + 40, 50, OTP_DLG_WIDTH - 40, 90};
            DrawTextW(memDC, L"Enter your passcode", -1, &titleRect, DT_LEFT | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);

            // Instruction
            HFONT instrFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, instrFont);
            SetTextColor(memDC, RGB(100, 100, 100));
            RECT instrRect = {LEFT_PANEL_WIDTH + 40, 110, OTP_DLG_WIDTH - 40, 150};
            DrawTextW(memDC, L"Enter the 6-digit code from your WorldPosta app", -1, &instrRect, DT_LEFT | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(instrFont);

            // Verify button (green)
            HBRUSH okBrush = CreateSolidBrush(WP_GREEN);
            HBRUSH oldBrush = (HBRUSH)SelectObject(memDC, okBrush);
            HPEN okPen = CreatePen(PS_SOLID, 1, WP_GREEN);
            HPEN oldPen = (HPEN)SelectObject(memDC, okPen);
            RoundRect(memDC, okButtonRect.left, okButtonRect.top, okButtonRect.right, okButtonRect.bottom, 8, 8);
            SelectObject(memDC, oldBrush);
            SelectObject(memDC, oldPen);
            DeleteObject(okBrush);
            DeleteObject(okPen);

            SetTextColor(memDC, WP_WHITE);
            HFONT btnFont = CreateFontW(15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, btnFont);
            DrawTextW(memDC, L"Verify", -1, &okButtonRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            // Cancel button (outline)
            HBRUSH cancelBrush = CreateSolidBrush(WP_WHITE);
            oldBrush = (HBRUSH)SelectObject(memDC, cancelBrush);
            HPEN cancelPen = CreatePen(PS_SOLID, 2, WP_DARK_BLUE);
            oldPen = (HPEN)SelectObject(memDC, cancelPen);
            RoundRect(memDC, cancelButtonRect.left, cancelButtonRect.top, cancelButtonRect.right, cancelButtonRect.bottom, 8, 8);
            SelectObject(memDC, oldBrush);
            SelectObject(memDC, oldPen);
            DeleteObject(cancelBrush);
            DeleteObject(cancelPen);

            SetTextColor(memDC, WP_DARK_BLUE);
            DrawTextW(memDC, L"Cancel", -1, &cancelButtonRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(memDC, oldFont);
            DeleteObject(btnFont);

            BitBlt(hdc, 0, 0, OTP_DLG_WIDTH, OTP_DLG_HEIGHT, memDC, 0, 0, SRCCOPY);

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
            POINT pt = {x, y};

            if (PtInRect(&okButtonRect, pt)) {
                wchar_t buffer[64] = {0};
                GetWindowTextW(hEdit, buffer, 64);
                g_otpResult = buffer;
                DestroyWindow(hwnd);
            } else if (PtInRect(&cancelButtonRect, pt)) {
                g_otpResult = L"";
                DestroyWindow(hwnd);
            }
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
    int dlgWidth = 720;
    int dlgHeight = 350;
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

// Push waiting dialog
static LRESULT CALLBACK PushWaitingWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static RECT cancelButtonRect = {0};
    const int PUSH_DLG_WIDTH = 720;
    const int PUSH_DLG_HEIGHT = 320;

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();
            LoadLogoImage();
            cancelButtonRect = {PUSH_DLG_WIDTH - 140, 240, PUSH_DLG_WIDTH - 20, 280};
        }
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, PUSH_DLG_WIDTH, PUSH_DLG_HEIGHT);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            RECT clientRect = {0, 0, PUSH_DLG_WIDTH, PUSH_DLG_HEIGHT};
            HBRUSH whiteBrush = CreateSolidBrush(WP_WHITE);
            FillRect(memDC, &clientRect, whiteBrush);
            DeleteObject(whiteBrush);

            // Left panel
            RECT leftPanel = {0, 0, LEFT_PANEL_WIDTH, PUSH_DLG_HEIGHT};
            HBRUSH leftBrush = CreateSolidBrush(RGB(250, 250, 250));
            FillRect(memDC, &leftPanel, leftBrush);
            DeleteObject(leftBrush);

            DrawWorldPostaLogo(memDC, LEFT_PANEL_WIDTH / 2, PUSH_DLG_HEIGHT / 2 - 20, 130);

            SetBkMode(memDC, TRANSPARENT);
            SetTextColor(memDC, WP_DARK_BLUE);
            HFONT smallFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, smallFont);
            RECT poweredRect = {0, PUSH_DLG_HEIGHT / 2 + 60, LEFT_PANEL_WIDTH, PUSH_DLG_HEIGHT / 2 + 90};
            DrawTextW(memDC, L"Powered by WorldPosta", -1, &poweredRect, DT_CENTER | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(smallFont);

            // Title
            HFONT titleFont = CreateFontW(22, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, titleFont);
            RECT titleRect = {LEFT_PANEL_WIDTH + 40, 80, PUSH_DLG_WIDTH - 40, 120};
            DrawTextW(memDC, L"Push notification sent", -1, &titleRect, DT_LEFT | DT_SINGLELINE);
            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);

            // Instruction
            HFONT instrFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            oldFont = (HFONT)SelectObject(memDC, instrFont);
            SetTextColor(memDC, RGB(100, 100, 100));
            RECT instrRect = {LEFT_PANEL_WIDTH + 40, 140, PUSH_DLG_WIDTH - 40, 200};
            DrawTextW(memDC, L"Please check your phone and approve\nthe authentication request.", -1, &instrRect, DT_LEFT);
            SelectObject(memDC, oldFont);
            DeleteObject(instrFont);

            // Cancel button
            HBRUSH btnBrush = CreateSolidBrush(WP_WHITE);
            HBRUSH oldBrush = (HBRUSH)SelectObject(memDC, btnBrush);
            HPEN btnPen = CreatePen(PS_SOLID, 2, WP_DARK_BLUE);
            HPEN oldPen = (HPEN)SelectObject(memDC, btnPen);
            RoundRect(memDC, cancelButtonRect.left, cancelButtonRect.top, cancelButtonRect.right, cancelButtonRect.bottom, 8, 8);
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

            BitBlt(hdc, 0, 0, PUSH_DLG_WIDTH, PUSH_DLG_HEIGHT, memDC, 0, 0, SRCCOPY);

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
            POINT pt = {x, y};
            if (PtInRect(&cancelButtonRect, pt)) {
                DestroyWindow(hwnd);
            }
        }
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

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
    int dlgWidth = 720;
    int dlgHeight = 320;
    int x = (screenWidth - dlgWidth) / 2;
    int y = (screenHeight - dlgHeight) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        WP_PUSH_WAITING_CLASS,
        L"WorldPosta Authentication",
        WS_POPUP | WS_CAPTION | WS_VISIBLE,
        x, y, dlgWidth, dlgHeight,
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
