#include "AuthDialog.h"
#include "logos.h"
#include <CommCtrl.h>
#include <windowsx.h>
#include <gdiplus.h>
#include <shlobj.h>
#include <thread>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdiplus.lib")

// Forward declaration for DLL module handle
extern HINSTANCE g_hinst;

// WorldPosta brand colors
#define WP_GREEN RGB(103, 154, 65)      // #679a41
#define WP_DARK_BLUE RGB(41, 60, 81)    // #293c51
#define WP_WHITE RGB(255, 255, 255)
#define WP_LIGHT_GRAY RGB(245, 245, 245)
#define WP_LIGHT_GRAY2 RGB(248, 249, 250)
#define WP_BORDER_GRAY RGB(220, 220, 220)
#define WP_ORANGE RGB(196, 144, 68)     // For pending badge
#define WP_TEXT_GRAY RGB(120, 120, 120)

// Dialog dimensions - new clean design
#define DLG_WIDTH 450
#define DLG_HEIGHT 580
#define LOGO_SIZE 50
#define LOCK_ICON_SIZE 80
#define LEFT_PANEL_WIDTH 260  // For OTP/Push dialogs

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

// Dialog states for the main auth dialog
enum class DialogState {
    CHOICE,     // Initial state - show Push/Passcode buttons
    WAITING,    // Waiting for push approval
    APPROVED,   // Push approved - green glow
    DENIED      // Push denied - red glow
};
static DialogState g_dialogState = DialogState::CHOICE;
static HWND g_mainDialogHwnd = NULL;

// Callbacks for push and OTP
static PushCallback g_pushCallback = nullptr;
static OTPVerifyCallback g_otpVerifyCallback = nullptr;

// Set push callback
void AuthDialog::SetPushCallback(PushCallback callback) {
    g_pushCallback = callback;
}

// Set OTP verify callback
void AuthDialog::SetOTPVerifyCallback(OTPVerifyCallback callback) {
    g_otpVerifyCallback = callback;
}

// GDI+ token and logo images
static ULONG_PTR g_gdiplusToken = 0;
static Gdiplus::Image* g_logoImage = nullptr;
static Gdiplus::Image* g_smallIconImage = nullptr;
static Gdiplus::Image* g_pushIconImage = nullptr;
static Gdiplus::Image* g_passcodeIconImage = nullptr;
static Gdiplus::Image* g_lockedIconImage = nullptr;
static Gdiplus::Image* g_unlockedIconImage = nullptr;

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

// Helper to load bitmap from resource
static Gdiplus::Bitmap* LoadBitmapFromResource(int resourceId) {
    HBITMAP hBitmap = (HBITMAP)LoadImageW(g_hinst, MAKEINTRESOURCEW(resourceId),
                                          IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);
    if (hBitmap) {
        Gdiplus::Bitmap* bitmap = Gdiplus::Bitmap::FromHBITMAP(hBitmap, NULL);
        DeleteObject(hBitmap);
        return bitmap;
    }
    return nullptr;
}

// Load logo images from embedded resources
static void LoadLogoImage() {
    InitGDIPlus();

    // Load main logo if not already loaded
    if (g_logoImage == nullptr) {
        g_logoImage = LoadBitmapFromResource(IDB_WP_LOGO);
    }

    // Load small icon if not already loaded
    if (g_smallIconImage == nullptr) {
        g_smallIconImage = LoadBitmapFromResource(IDB_WP_SMALL_ICON);
    }

    // Load push icon if not already loaded
    if (g_pushIconImage == nullptr) {
        g_pushIconImage = LoadBitmapFromResource(IDB_WP_PUSH_ICON);
    }

    // Load passcode icon if not already loaded
    if (g_passcodeIconImage == nullptr) {
        g_passcodeIconImage = LoadBitmapFromResource(IDB_WP_PASSCODE_ICON);
    }

    // Load locked icon if not already loaded
    if (g_lockedIconImage == nullptr) {
        g_lockedIconImage = LoadBitmapFromResource(IDB_WP_LOCKED_ICON);
    }

    // Load unlocked icon if not already loaded
    if (g_unlockedIconImage == nullptr) {
        g_unlockedIconImage = LoadBitmapFromResource(IDB_WP_UNLOCKED_ICON);
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
// Icon types for auth buttons
enum class AuthIconType { PUSH, PASSCODE };

static void DrawAuthOptionButton(HDC hdc, RECT* rect, const wchar_t* title, const wchar_t* subtitle, bool hover, AuthIconType iconType) {
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

    // Icon on left - draw the appropriate icon based on type
    int iconSize = 45;
    int iconX = rect->left + 20;
    int iconY = rect->top + (rect->bottom - rect->top - iconSize) / 2;

    // Load images if needed
    LoadLogoImage();

    // Select the appropriate icon
    Gdiplus::Image* iconImage = nullptr;
    if (iconType == AuthIconType::PUSH && g_pushIconImage != nullptr) {
        iconImage = g_pushIconImage;
    } else if (iconType == AuthIconType::PASSCODE && g_passcodeIconImage != nullptr) {
        iconImage = g_passcodeIconImage;
    } else if (g_smallIconImage != nullptr) {
        iconImage = g_smallIconImage;  // Fallback to generic icon
    }

    if (iconImage != nullptr) {
        graphics.DrawImage(iconImage, iconX, iconY, iconSize, iconSize);
    } else {
        // Fallback: draw green circle if no image loaded
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

// Custom message for push result
#define WM_PUSH_RESULT (WM_USER + 100)

// Main dialog window procedure - New clean design
static LRESULT CALLBACK AuthDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static int hoveredButton = 0;  // 0=none, 1=push, 2=passcode, 3=cancel
    static RECT pushButtonRect = {0};
    static RECT passcodeButtonRect = {0};
    static RECT cancelLinkRect = {0};

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();
            LoadLogoImage();

            // Store HWND and reset state
            g_mainDialogHwnd = hwnd;
            g_dialogState = DialogState::CHOICE;

            // Calculate button positions for new design
            int btnWidth = DLG_WIDTH - 60;
            int btnHeight = 50;
            int centerX = DLG_WIDTH / 2;

            // Push button - green primary button
            pushButtonRect = {30, 380, DLG_WIDTH - 30, 380 + btnHeight};

            // Passcode button - white secondary button
            passcodeButtonRect = {30, 445, DLG_WIDTH - 30, 445 + btnHeight};

            // Cancel link at bottom
            cancelLinkRect = {centerX - 80, 510, centerX + 80, 535};
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

            // Fill background with light gray
            RECT clientRect = {0, 0, DLG_WIDTH, DLG_HEIGHT};
            HBRUSH bgBrush = CreateSolidBrush(WP_LIGHT_GRAY2);
            FillRect(memDC, &clientRect, bgBrush);
            DeleteObject(bgBrush);

            SetBkMode(memDC, TRANSPARENT);

            // ===== HEADER SECTION =====
            // Draw logo (small, top left)
            if (g_logoImage != nullptr) {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
                graphics.DrawImage(g_logoImage, 25, 20, LOGO_SIZE, LOGO_SIZE);
            }

            // Title: "WorldPosta Authenticator"
            HFONT titleFont = CreateFontW(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, titleFont);
            SetTextColor(memDC, WP_DARK_BLUE);
            RECT titleRect = {85, 25, DLG_WIDTH - 100, 50};
            DrawTextW(memDC, L"WorldPosta Authenticator", -1, &titleRect, DT_LEFT | DT_SINGLELINE);

            // Subtitle: "IDENTITY VERIFICATION"
            HFONT subtitleFont = CreateFontW(11, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, subtitleFont);
            SetTextColor(memDC, WP_GREEN);
            RECT subtitleRect = {85, 48, DLG_WIDTH - 100, 65};
            DrawTextW(memDC, L"IDENTITY VERIFICATION", -1, &subtitleRect, DT_LEFT | DT_SINGLELINE);

            // Status badge (top right) - changes based on state
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                Gdiplus::GraphicsPath badgePath;
                int badgeX = DLG_WIDTH - 105, badgeY = 28, badgeW = 80, badgeH = 24;
                badgePath.AddArc(badgeX, badgeY, 12, 12, 180, 90);
                badgePath.AddArc(badgeX + badgeW - 12, badgeY, 12, 12, 270, 90);
                badgePath.AddArc(badgeX + badgeW - 12, badgeY + badgeH - 12, 12, 12, 0, 90);
                badgePath.AddArc(badgeX, badgeY + badgeH - 12, 12, 12, 90, 90);
                badgePath.CloseFigure();

                Gdiplus::Color bgColor, dotColor, txtColor;
                const wchar_t* badgeText = L"PENDING";

                switch (g_dialogState) {
                case DialogState::WAITING:
                    bgColor = Gdiplus::Color(255, 255, 248, 230);
                    dotColor = Gdiplus::Color(255, 196, 144, 68);
                    txtColor = Gdiplus::Color(255, 196, 144, 68);
                    badgeText = L"WAITING";
                    break;
                case DialogState::APPROVED:
                    bgColor = Gdiplus::Color(255, 230, 255, 230);
                    dotColor = Gdiplus::Color(255, 103, 154, 65);
                    txtColor = Gdiplus::Color(255, 103, 154, 65);
                    badgeText = L"APPROVED";
                    badgeW = 90;
                    break;
                case DialogState::DENIED:
                    bgColor = Gdiplus::Color(255, 255, 230, 230);
                    dotColor = Gdiplus::Color(255, 200, 80, 80);
                    txtColor = Gdiplus::Color(255, 200, 80, 80);
                    badgeText = L"DENIED";
                    break;
                default: // CHOICE
                    bgColor = Gdiplus::Color(255, 255, 248, 230);
                    dotColor = Gdiplus::Color(255, 196, 144, 68);
                    txtColor = Gdiplus::Color(255, 196, 144, 68);
                    badgeText = L"PENDING";
                    break;
                }

                Gdiplus::SolidBrush badgeBrush(bgColor);
                graphics.FillPath(&badgeBrush, &badgePath);

                Gdiplus::SolidBrush dotBrush(dotColor);
                graphics.FillEllipse(&dotBrush, badgeX + 10, badgeY + 8, 8, 8);

                Gdiplus::FontFamily fontFamily(L"Segoe UI");
                Gdiplus::Font badgeFont(&fontFamily, 9, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::SolidBrush textBrush(txtColor);
                graphics.DrawString(badgeText, -1, &badgeFont, Gdiplus::PointF((float)badgeX + 22, (float)badgeY + 5), &textBrush);
            }

            // ===== LOCK ICON SECTION =====
            // White circle with shadow/glow effect based on state
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                int circleX = DLG_WIDTH / 2;
                int circleY = 175;
                int circleRadius = 75;

                // Glow/Shadow based on state
                if (g_dialogState == DialogState::APPROVED) {
                    // Green glow for approved
                    for (int i = 5; i >= 0; i--) {
                        int glowRadius = circleRadius + 8 + i * 5;
                        int alpha = 35 - i * 5;
                        Gdiplus::SolidBrush glowBrush(Gdiplus::Color(alpha, 103, 154, 65));
                        graphics.FillEllipse(&glowBrush, circleX - glowRadius, circleY - glowRadius, glowRadius * 2, glowRadius * 2);
                    }
                } else if (g_dialogState == DialogState::DENIED) {
                    // Red glow for denied
                    for (int i = 5; i >= 0; i--) {
                        int glowRadius = circleRadius + 8 + i * 5;
                        int alpha = 35 - i * 5;
                        Gdiplus::SolidBrush glowBrush(Gdiplus::Color(alpha, 200, 80, 80));
                        graphics.FillEllipse(&glowBrush, circleX - glowRadius, circleY - glowRadius, glowRadius * 2, glowRadius * 2);
                    }
                } else {
                    // Normal shadow
                    for (int i = 3; i >= 0; i--) {
                        int shadowOffset = 4 + i * 2;
                        int alpha = 8 + i * 5;
                        Gdiplus::SolidBrush shadowBrush(Gdiplus::Color(alpha, 0, 0, 0));
                        graphics.FillEllipse(&shadowBrush, circleX - circleRadius + shadowOffset,
                                            circleY - circleRadius + shadowOffset,
                                            circleRadius * 2, circleRadius * 2);
                    }
                }

                // White circle with colored border for approved/denied
                Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255, 255));
                graphics.FillEllipse(&whiteBrush, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);

                if (g_dialogState == DialogState::APPROVED) {
                    Gdiplus::Pen borderPen(Gdiplus::Color(255, 103, 154, 65), 3);
                    graphics.DrawEllipse(&borderPen, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);
                } else if (g_dialogState == DialogState::DENIED) {
                    Gdiplus::Pen borderPen(Gdiplus::Color(255, 200, 80, 80), 3);
                    graphics.DrawEllipse(&borderPen, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);
                }

                // Draw shield icon - different based on state
                {
                    int shieldCX = circleX;
                    int shieldCY = circleY - 5;
                    int shieldW = 50;
                    int shieldH = 58;

                    // Shield path
                    Gdiplus::GraphicsPath shieldPath;
                    shieldPath.StartFigure();
                    shieldPath.AddLine(shieldCX - shieldW/2, shieldCY - shieldH/2 + 8, shieldCX - shieldW/2, shieldCY + 5);
                    shieldPath.AddBezier(shieldCX - shieldW/2, shieldCY + 5, shieldCX - shieldW/2, shieldCY + shieldH/2 - 10,
                                        shieldCX, shieldCY + shieldH/2, shieldCX, shieldCY + shieldH/2);
                    shieldPath.AddBezier(shieldCX, shieldCY + shieldH/2, shieldCX, shieldCY + shieldH/2,
                                        shieldCX + shieldW/2, shieldCY + shieldH/2 - 10, shieldCX + shieldW/2, shieldCY + 5);
                    shieldPath.AddLine(shieldCX + shieldW/2, shieldCY + 5, shieldCX + shieldW/2, shieldCY - shieldH/2 + 8);
                    shieldPath.AddArc(shieldCX - shieldW/2, shieldCY - shieldH/2, 16, 16, 180, 90);
                    shieldPath.AddLine(shieldCX - shieldW/2 + 8, shieldCY - shieldH/2, shieldCX + shieldW/2 - 8, shieldCY - shieldH/2);
                    shieldPath.AddArc(shieldCX + shieldW/2 - 16, shieldCY - shieldH/2, 16, 16, 270, 90);
                    shieldPath.CloseFigure();

                    Gdiplus::Color shieldColor;
                    if (g_dialogState == DialogState::APPROVED) {
                        shieldColor = Gdiplus::Color(255, 103, 154, 65);
                    } else if (g_dialogState == DialogState::DENIED) {
                        shieldColor = Gdiplus::Color(255, 200, 80, 80);
                    } else {
                        shieldColor = Gdiplus::Color(255, 140, 150, 160);
                    }

                    Gdiplus::Pen shieldPen(shieldColor, 2.5f);
                    graphics.DrawPath(&shieldPen, &shieldPath);

                    // Draw icon inside shield based on state
                    if (g_dialogState == DialogState::APPROVED) {
                        // Checkmark for approved
                        Gdiplus::Pen checkPen(shieldColor, 3.5f);
                        checkPen.SetStartCap(Gdiplus::LineCapRound);
                        checkPen.SetEndCap(Gdiplus::LineCapRound);
                        checkPen.SetLineJoin(Gdiplus::LineJoinRound);
                        graphics.DrawLine(&checkPen, shieldCX - 12, shieldCY, shieldCX - 3, shieldCY + 10);
                        graphics.DrawLine(&checkPen, shieldCX - 3, shieldCY + 10, shieldCX + 14, shieldCY - 8);
                    } else if (g_dialogState == DialogState::DENIED) {
                        // X for denied
                        Gdiplus::Pen xPen(shieldColor, 3.5f);
                        xPen.SetStartCap(Gdiplus::LineCapRound);
                        xPen.SetEndCap(Gdiplus::LineCapRound);
                        graphics.DrawLine(&xPen, shieldCX - 10, shieldCY - 10, shieldCX + 10, shieldCY + 10);
                        graphics.DrawLine(&xPen, shieldCX + 10, shieldCY - 10, shieldCX - 10, shieldCY + 10);
                    } else {
                        // Exclamation mark for pending/waiting
                        Gdiplus::Pen exclPen(shieldColor, 3.0f);
                        exclPen.SetStartCap(Gdiplus::LineCapRound);
                        exclPen.SetEndCap(Gdiplus::LineCapRound);
                        graphics.DrawLine(&exclPen, shieldCX, shieldCY - 12, shieldCX, shieldCY + 8);
                        Gdiplus::SolidBrush dotBrush(shieldColor);
                        graphics.FillEllipse(&dotBrush, shieldCX - 3, shieldCY + 14, 6, 6);
                    }
                }
            }

            // Status text below the circle - changes based on state
            HFONT lockedFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, lockedFont);

            const wchar_t* statusText = L"L O C K E D";
            COLORREF statusColor = RGB(180, 180, 180);

            switch (g_dialogState) {
            case DialogState::WAITING:
                statusText = L"W A I T I N G";
                statusColor = RGB(196, 144, 68);
                break;
            case DialogState::APPROVED:
                statusText = L"A C C E S S   G R A N T E D";
                statusColor = RGB(103, 154, 65);
                break;
            case DialogState::DENIED:
                statusText = L"A C C E S S   D E N I E D";
                statusColor = RGB(200, 80, 80);
                break;
            default:
                statusText = L"L O C K E D";
                statusColor = RGB(180, 180, 180);
                break;
            }

            SetTextColor(memDC, statusColor);
            RECT lockedRect = {0, 258, DLG_WIDTH, 278};
            DrawTextW(memDC, statusText, -1, &lockedRect, DT_CENTER | DT_SINGLELINE);

            // ===== CONTENT SECTION ===== (changes based on state)
            HFONT authTitleFont = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, authTitleFont);

            HFONT descFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

            const wchar_t* titleText = L"Authorize Session";
            const wchar_t* descText = L"To continue, please confirm this sign-in\nrequest on your mobile device.";
            COLORREF titleColor = WP_DARK_BLUE;

            switch (g_dialogState) {
            case DialogState::WAITING:
                titleText = L"Waiting for Approval";
                descText = L"Please check your mobile device and approve\nthe authentication request.";
                titleColor = WP_DARK_BLUE;
                break;
            case DialogState::APPROVED:
                titleText = L"Authentication Successful";
                descText = L"Your identity has been verified.\nYou will be signed in shortly.";
                titleColor = RGB(103, 154, 65);
                break;
            case DialogState::DENIED:
                titleText = L"Authentication Failed";
                descText = L"The request was denied or timed out.\nPlease try again.";
                titleColor = RGB(200, 80, 80);
                break;
            default:
                break;
            }

            SetTextColor(memDC, titleColor);
            RECT authTitleRect = {0, 290, DLG_WIDTH, 320};
            DrawTextW(memDC, titleText, -1, &authTitleRect, DT_CENTER | DT_SINGLELINE);

            SelectObject(memDC, descFont);
            SetTextColor(memDC, WP_TEXT_GRAY);
            RECT descRect = {30, 325, DLG_WIDTH - 30, 370};
            DrawTextW(memDC, descText, -1, &descRect, DT_CENTER);

            // ===== BUTTONS ===== (only show in CHOICE state)
            if (g_dialogState == DialogState::CHOICE) {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                // Push button (green)
                Gdiplus::GraphicsPath pushPath;
                int r = 8;
                pushPath.AddArc(pushButtonRect.left, pushButtonRect.top, r*2, r*2, 180, 90);
                pushPath.AddArc(pushButtonRect.right - r*2, pushButtonRect.top, r*2, r*2, 270, 90);
                pushPath.AddArc(pushButtonRect.right - r*2, pushButtonRect.bottom - r*2, r*2, r*2, 0, 90);
                pushPath.AddArc(pushButtonRect.left, pushButtonRect.bottom - r*2, r*2, r*2, 90, 90);
                pushPath.CloseFigure();

                Gdiplus::Color pushColor = hoveredButton == 1 ? Gdiplus::Color(255, 85, 135, 55) : Gdiplus::Color(255, 103, 154, 65);
                Gdiplus::SolidBrush pushBrush(pushColor);
                graphics.FillPath(&pushBrush, &pushPath);

                // Draw phone icon on push button
                {
                    int iconX = pushButtonRect.left + 55;
                    int iconY = (pushButtonRect.top + pushButtonRect.bottom) / 2;

                    Gdiplus::GraphicsPath phonePath;
                    phonePath.AddArc(iconX - 8, iconY - 12, 4, 4, 180, 90);
                    phonePath.AddArc(iconX + 4, iconY - 12, 4, 4, 270, 90);
                    phonePath.AddArc(iconX + 4, iconY + 8, 4, 4, 0, 90);
                    phonePath.AddArc(iconX - 8, iconY + 8, 4, 4, 90, 90);
                    phonePath.CloseFigure();

                    Gdiplus::Pen phonePen(Gdiplus::Color(255, 255, 255, 255), 1.5f);
                    graphics.DrawPath(&phonePen, &phonePath);
                    graphics.DrawLine(&phonePen, iconX - 4, iconY - 7, iconX + 4, iconY - 7);
                    Gdiplus::SolidBrush whiteBrush2(Gdiplus::Color(255, 255, 255, 255));
                    graphics.FillEllipse(&whiteBrush2, iconX - 2, iconY + 5, 4, 4);
                }

                Gdiplus::FontFamily fontFamily(L"Segoe UI");
                Gdiplus::Font btnFont(&fontFamily, 14, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255, 255));
                Gdiplus::StringFormat sf;
                sf.SetAlignment(Gdiplus::StringAlignmentCenter);
                sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
                Gdiplus::RectF pushRectF((float)pushButtonRect.left + 25, (float)pushButtonRect.top,
                                         (float)(pushButtonRect.right - pushButtonRect.left) - 25,
                                         (float)(pushButtonRect.bottom - pushButtonRect.top));
                graphics.DrawString(L"Push to my device", -1, &btnFont, pushRectF, &sf, &whiteBrush);

                // Passcode button (white with border)
                Gdiplus::GraphicsPath passcodePath;
                passcodePath.AddArc(passcodeButtonRect.left, passcodeButtonRect.top, r*2, r*2, 180, 90);
                passcodePath.AddArc(passcodeButtonRect.right - r*2, passcodeButtonRect.top, r*2, r*2, 270, 90);
                passcodePath.AddArc(passcodeButtonRect.right - r*2, passcodeButtonRect.bottom - r*2, r*2, r*2, 0, 90);
                passcodePath.AddArc(passcodeButtonRect.left, passcodeButtonRect.bottom - r*2, r*2, r*2, 90, 90);
                passcodePath.CloseFigure();

                Gdiplus::Color passcodeColor = hoveredButton == 2 ? Gdiplus::Color(255, 245, 245, 245) : Gdiplus::Color(255, 255, 255, 255);
                Gdiplus::SolidBrush passcodeBrush(passcodeColor);
                graphics.FillPath(&passcodeBrush, &passcodePath);
                Gdiplus::Pen borderPen(Gdiplus::Color(255, 220, 220, 220), 1);
                graphics.DrawPath(&borderPen, &passcodePath);

                // Draw key icon
                {
                    int iconX = passcodeButtonRect.left + 55;
                    int iconY = (passcodeButtonRect.top + passcodeButtonRect.bottom) / 2;
                    Gdiplus::Pen keyPen(Gdiplus::Color(255, 100, 100, 100), 1.8f);
                    keyPen.SetStartCap(Gdiplus::LineCapRound);
                    keyPen.SetEndCap(Gdiplus::LineCapRound);
                    graphics.DrawEllipse(&keyPen, iconX - 10, iconY - 7, 10, 10);
                    graphics.DrawLine(&keyPen, iconX - 2, iconY - 2, iconX + 8, iconY + 8);
                    graphics.DrawLine(&keyPen, iconX + 4, iconY + 4, iconX + 4, iconY + 7);
                    graphics.DrawLine(&keyPen, iconX + 7, iconY + 7, iconX + 7, iconY + 10);
                }

                Gdiplus::SolidBrush darkBrush(Gdiplus::Color(255, 80, 80, 80));
                Gdiplus::RectF passcodeRectF((float)passcodeButtonRect.left + 25, (float)passcodeButtonRect.top,
                                             (float)(passcodeButtonRect.right - passcodeButtonRect.left) - 25,
                                             (float)(passcodeButtonRect.bottom - passcodeButtonRect.top));
                graphics.DrawString(L"Passcode", -1, &btnFont, passcodeRectF, &sf, &darkBrush);

                // Cancel link
                int cancelCX = DLG_WIDTH / 2;
                int cancelCY = cancelLinkRect.top + 8;
                Gdiplus::Color cancelColor = hoveredButton == 3 ? Gdiplus::Color(255, 80, 80, 80) : Gdiplus::Color(255, 150, 150, 150);
                Gdiplus::Pen circlePen(cancelColor, 1.2f);
                graphics.DrawEllipse(&circlePen, cancelCX - 55, cancelCY - 6, 12, 12);
                graphics.DrawLine(&circlePen, cancelCX - 52, cancelCY - 3, cancelCX - 46, cancelCY + 3);
                graphics.DrawLine(&circlePen, cancelCX - 46, cancelCY - 3, cancelCX - 52, cancelCY + 3);

                Gdiplus::Font cancelFontGdi(&fontFamily, 11, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::SolidBrush cancelBrush(cancelColor);
                Gdiplus::RectF cancelRectF((float)cancelLinkRect.left + 15, (float)cancelLinkRect.top,
                                           (float)(cancelLinkRect.right - cancelLinkRect.left),
                                           (float)(cancelLinkRect.bottom - cancelLinkRect.top));
                graphics.DrawString(L"CANCEL REQUEST", -1, &cancelFontGdi, cancelRectF, &sf, &cancelBrush);
            }
            // Show loading animation in WAITING state
            else if (g_dialogState == DialogState::WAITING) {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                // Loading dots
                int dotY = 420;
                int dotRadius = 6;
                int dotSpacing = 25;
                int startX = DLG_WIDTH / 2 - dotSpacing;

                Gdiplus::SolidBrush dot1(Gdiplus::Color(255, 103, 154, 65));
                Gdiplus::SolidBrush dot2(Gdiplus::Color(150, 103, 154, 65));
                Gdiplus::SolidBrush dot3(Gdiplus::Color(80, 103, 154, 65));

                graphics.FillEllipse(&dot1, startX - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);
                graphics.FillEllipse(&dot2, startX + dotSpacing - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);
                graphics.FillEllipse(&dot3, startX + dotSpacing * 2 - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);

                // Cancel link during waiting
                Gdiplus::FontFamily fontFamily(L"Segoe UI");
                Gdiplus::Font cancelFontGdi(&fontFamily, 11, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::Color cancelColor = hoveredButton == 3 ? Gdiplus::Color(255, 80, 80, 80) : Gdiplus::Color(255, 150, 150, 150);
                Gdiplus::SolidBrush cancelBrush(cancelColor);
                Gdiplus::StringFormat sf;
                sf.SetAlignment(Gdiplus::StringAlignmentCenter);
                sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
                Gdiplus::RectF cancelRectF((float)cancelLinkRect.left, (float)cancelLinkRect.top,
                                           (float)(cancelLinkRect.right - cancelLinkRect.left),
                                           (float)(cancelLinkRect.bottom - cancelLinkRect.top));
                graphics.DrawString(L"Cancel", -1, &cancelFontGdi, cancelRectF, &sf, &cancelBrush);
            }

            // ===== FOOTER =====
            RECT footerRect = {0, DLG_HEIGHT - 40, DLG_WIDTH, DLG_HEIGHT};
            HBRUSH footerBrush = CreateSolidBrush(WP_LIGHT_GRAY);
            FillRect(memDC, &footerRect, footerBrush);
            DeleteObject(footerBrush);

            // Footer text
            HFONT footerFont = CreateFontW(10, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, footerFont);

            // Green dot + "SECURE NODE ACTIVE"
            SetTextColor(memDC, WP_GREEN);
            RECT statusRect = {20, DLG_HEIGHT - 28, 180, DLG_HEIGHT - 12};
            DrawTextW(memDC, L"\u25CF SECURE NODE ACTIVE", -1, &statusRect, DT_LEFT | DT_SINGLELINE);

            // Version
            SetTextColor(memDC, WP_TEXT_GRAY);
            RECT versionRect = {DLG_WIDTH - 100, DLG_HEIGHT - 28, DLG_WIDTH - 20, DLG_HEIGHT - 12};
            DrawTextW(memDC, L"WP-AUTH V1.0.0", -1, &versionRect, DT_RIGHT | DT_SINGLELINE);

            // Cleanup fonts
            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);
            DeleteObject(subtitleFont);
            DeleteObject(lockedFont);
            DeleteObject(authTitleFont);
            DeleteObject(descFont);
            DeleteObject(footerFont);

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
            else if (PtInRect(&passcodeButtonRect, pt)) newHover = 2;
            else if (PtInRect(&cancelLinkRect, pt)) newHover = 3;

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

            if (g_dialogState == DialogState::CHOICE) {
                if (PtInRect(&pushButtonRect, pt)) {
                    // Close dialog and return PUSH choice
                    // CCredential will handle showing waiting dialog and sending push
                    g_authChoice = AuthMethod::PUSH;
                    DestroyWindow(hwnd);
                } else if (PtInRect(&passcodeButtonRect, pt)) {
                    g_authChoice = AuthMethod::OTP;
                    DestroyWindow(hwnd);
                } else if (PtInRect(&cancelLinkRect, pt)) {
                    g_authChoice = AuthMethod::CANCEL;
                    DestroyWindow(hwnd);
                }
            } else if (g_dialogState == DialogState::WAITING) {
                if (PtInRect(&cancelLinkRect, pt)) {
                    g_authChoice = AuthMethod::CANCEL;
                    g_dialogState = DialogState::CHOICE;
                    DestroyWindow(hwnd);
                }
            } else if (g_dialogState == DialogState::APPROVED || g_dialogState == DialogState::DENIED) {
                // Click anywhere to close after result shown
                DestroyWindow(hwnd);
            }
        }
        return 0;

    case WM_PUSH_RESULT:
        {
            // wParam: 0 = start push, 1 = approved, 2 = denied/timeout
            if (wParam == 0) {
                // Push started - call the push callback to trigger actual push
                if (g_pushCallback) {
                    // Run push in background thread
                    std::thread([hwnd]() {
                        g_pushCallback();
                    }).detach();
                }
            } else if (wParam == 1) {
                // Approved
                g_dialogState = DialogState::APPROVED;
                g_authChoice = AuthMethod::PUSH;
                InvalidateRect(hwnd, NULL, FALSE);
                // Close after 1.5 seconds
                SetTimer(hwnd, 1, 1500, NULL);
            } else {
                // Denied or timeout - keep g_authChoice as PUSH so caller knows push was attempted
                g_dialogState = DialogState::DENIED;
                // g_authChoice stays as PUSH - the caller checks _piStatus for actual result
                InvalidateRect(hwnd, NULL, FALSE);
                // Close after 2 seconds
                SetTimer(hwnd, 1, 2000, NULL);
            }
        }
        return 0;

    case WM_TIMER:
        if (wParam == 1) {
            KillTimer(hwnd, 1);
            DestroyWindow(hwnd);
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
        g_mainDialogHwnd = NULL;
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// Helper function to send push result to the dialog
void AuthDialog::NotifyPushResult(bool approved) {
    if (g_mainDialogHwnd && IsWindow(g_mainDialogHwnd)) {
        PostMessage(g_mainDialogHwnd, WM_PUSH_RESULT, approved ? 1 : 2, 0);
    }
}

// Check if dialog is in waiting state
bool AuthDialog::IsWaitingForPush() {
    return g_dialogState == DialogState::WAITING && g_mainDialogHwnd != NULL;
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

// OTP dialog states
enum class OTPDialogState {
    INPUT,      // Entering code
    VERIFYING,  // Verifying code
    SUCCESS,    // Code verified
    FAILURE     // Code invalid
};
static OTPDialogState g_otpDialogState = OTPDialogState::INPUT;
static HWND g_otpDialogHwnd = NULL;

// Custom message for OTP verify result
#define WM_OTP_RESULT (WM_USER + 101)

// OTP Input Dialog - New clean design with state flow like push
static LRESULT CALLBACK OTPDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit = NULL;
    static RECT verifyButtonRect = {0};
    static RECT cancelLinkRect = {0};
    static int hoveredItem = 0;  // 0=none, 1=verify, 2=cancel
    static std::wstring enteredCode;

    const int OTP_DLG_WIDTH = 420;
    const int OTP_DLG_HEIGHT = 580;

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();
            LoadLogoImage();
            g_otpDialogHwnd = hwnd;
            g_otpDialogState = OTPDialogState::INPUT;
            enteredCode.clear();

            // Create edit control - centered in dialog
            hEdit = CreateWindowExW(
                0,
                L"EDIT",
                L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER | ES_NUMBER,
                50, 320,
                OTP_DLG_WIDTH - 100, 50,
                hwnd, (HMENU)IDC_OTP_EDIT, NULL, NULL
            );

            HFONT editFont = CreateFontW(32, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SendMessage(hEdit, WM_SETFONT, (WPARAM)editFont, TRUE);
            SetFocus(hEdit);

            // Verify button
            verifyButtonRect = {30, 390, OTP_DLG_WIDTH - 30, 440};

            // Cancel link
            cancelLinkRect = {OTP_DLG_WIDTH/2 - 60, 455, OTP_DLG_WIDTH/2 + 60, 480};
        }
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, OTP_DLG_WIDTH, OTP_DLG_HEIGHT);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            // Fill background with light gray
            RECT clientRect = {0, 0, OTP_DLG_WIDTH, OTP_DLG_HEIGHT};
            HBRUSH bgBrush = CreateSolidBrush(WP_LIGHT_GRAY2);
            FillRect(memDC, &clientRect, bgBrush);
            DeleteObject(bgBrush);

            SetBkMode(memDC, TRANSPARENT);

            // ===== HEADER SECTION =====
            if (g_logoImage != nullptr) {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
                graphics.DrawImage(g_logoImage, 25, 20, LOGO_SIZE, LOGO_SIZE);
            }

            // Title: "WorldPosta Authenticator"
            HFONT titleFont = CreateFontW(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, titleFont);
            SetTextColor(memDC, WP_DARK_BLUE);
            RECT titleRect = {85, 25, OTP_DLG_WIDTH - 30, 50};
            DrawTextW(memDC, L"WorldPosta Authenticator", -1, &titleRect, DT_LEFT | DT_SINGLELINE);

            // Subtitle badge - changes based on state
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                const wchar_t* badgeText = L"VERIFICATION";
                Gdiplus::Color bgColor(255, 103, 154, 65);
                Gdiplus::Color txtColor(255, 255, 255, 255);

                switch (g_otpDialogState) {
                case OTPDialogState::VERIFYING:
                    badgeText = L"VERIFYING";
                    bgColor = Gdiplus::Color(255, 196, 144, 68);
                    break;
                case OTPDialogState::SUCCESS:
                    badgeText = L"VERIFIED";
                    bgColor = Gdiplus::Color(255, 103, 154, 65);
                    break;
                case OTPDialogState::FAILURE:
                    badgeText = L"FAILED";
                    bgColor = Gdiplus::Color(255, 200, 80, 80);
                    break;
                default:
                    break;
                }

                int badgeX = 85;
                int badgeY = 48;
                Gdiplus::GraphicsPath badgePath;
                badgePath.AddArc(badgeX, badgeY, 10, 14, 180, 90);
                badgePath.AddArc(badgeX + 80, badgeY, 10, 14, 270, 90);
                badgePath.AddArc(badgeX + 80, badgeY + 6, 10, 14, 0, 90);
                badgePath.AddArc(badgeX, badgeY + 6, 10, 14, 90, 90);
                badgePath.CloseFigure();

                Gdiplus::SolidBrush badgeBrush(bgColor);
                graphics.FillPath(&badgeBrush, &badgePath);

                Gdiplus::FontFamily fontFamily(L"Segoe UI");
                Gdiplus::Font badgeFont(&fontFamily, 9, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::SolidBrush textBrush(txtColor);
                graphics.DrawString(badgeText, -1, &badgeFont, Gdiplus::PointF((float)badgeX + 12, (float)badgeY + 5), &textBrush);
            }

            // ===== SHIELD ICON SECTION WITH STATE-BASED GLOW =====
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                int circleX = OTP_DLG_WIDTH / 2;
                int circleY = 175;
                int circleRadius = 75;

                // Glow/Shadow based on state
                if (g_otpDialogState == OTPDialogState::SUCCESS) {
                    // Green glow for success
                    for (int i = 5; i >= 0; i--) {
                        int glowRadius = circleRadius + 8 + i * 5;
                        int alpha = 35 - i * 5;
                        Gdiplus::SolidBrush glowBrush(Gdiplus::Color(alpha, 103, 154, 65));
                        graphics.FillEllipse(&glowBrush, circleX - glowRadius, circleY - glowRadius, glowRadius * 2, glowRadius * 2);
                    }
                } else if (g_otpDialogState == OTPDialogState::FAILURE) {
                    // Red glow for failure
                    for (int i = 5; i >= 0; i--) {
                        int glowRadius = circleRadius + 8 + i * 5;
                        int alpha = 35 - i * 5;
                        Gdiplus::SolidBrush glowBrush(Gdiplus::Color(alpha, 200, 80, 80));
                        graphics.FillEllipse(&glowBrush, circleX - glowRadius, circleY - glowRadius, glowRadius * 2, glowRadius * 2);
                    }
                } else {
                    // Normal shadow
                    for (int i = 3; i >= 0; i--) {
                        int shadowOffset = 4 + i * 2;
                        int alpha = 8 + i * 5;
                        Gdiplus::SolidBrush shadowBrush(Gdiplus::Color(alpha, 0, 0, 0));
                        graphics.FillEllipse(&shadowBrush, circleX - circleRadius + shadowOffset,
                                            circleY - circleRadius + shadowOffset,
                                            circleRadius * 2, circleRadius * 2);
                    }
                }

                // White circle with colored border for success/failure
                Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255, 255));
                graphics.FillEllipse(&whiteBrush, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);

                if (g_otpDialogState == OTPDialogState::SUCCESS) {
                    Gdiplus::Pen borderPen(Gdiplus::Color(255, 103, 154, 65), 3);
                    graphics.DrawEllipse(&borderPen, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);
                } else if (g_otpDialogState == OTPDialogState::FAILURE) {
                    Gdiplus::Pen borderPen(Gdiplus::Color(255, 200, 80, 80), 3);
                    graphics.DrawEllipse(&borderPen, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);
                }

                // Draw shield icon - different based on state
                {
                    int shieldCX = circleX;
                    int shieldCY = circleY - 5;
                    int shieldW = 50;
                    int shieldH = 58;

                    // Shield path
                    Gdiplus::GraphicsPath shieldPath;
                    shieldPath.StartFigure();
                    shieldPath.AddLine(shieldCX - shieldW/2, shieldCY - shieldH/2 + 8, shieldCX - shieldW/2, shieldCY + 5);
                    shieldPath.AddBezier(shieldCX - shieldW/2, shieldCY + 5, shieldCX - shieldW/2, shieldCY + shieldH/2 - 10,
                                        shieldCX, shieldCY + shieldH/2, shieldCX, shieldCY + shieldH/2);
                    shieldPath.AddBezier(shieldCX, shieldCY + shieldH/2, shieldCX, shieldCY + shieldH/2,
                                        shieldCX + shieldW/2, shieldCY + shieldH/2 - 10, shieldCX + shieldW/2, shieldCY + 5);
                    shieldPath.AddLine(shieldCX + shieldW/2, shieldCY + 5, shieldCX + shieldW/2, shieldCY - shieldH/2 + 8);
                    shieldPath.AddArc(shieldCX - shieldW/2, shieldCY - shieldH/2, 16, 16, 180, 90);
                    shieldPath.AddLine(shieldCX - shieldW/2 + 8, shieldCY - shieldH/2, shieldCX + shieldW/2 - 8, shieldCY - shieldH/2);
                    shieldPath.AddArc(shieldCX + shieldW/2 - 16, shieldCY - shieldH/2, 16, 16, 270, 90);
                    shieldPath.CloseFigure();

                    Gdiplus::Color shieldColor;
                    if (g_otpDialogState == OTPDialogState::SUCCESS) {
                        shieldColor = Gdiplus::Color(255, 103, 154, 65);
                    } else if (g_otpDialogState == OTPDialogState::FAILURE) {
                        shieldColor = Gdiplus::Color(255, 200, 80, 80);
                    } else {
                        shieldColor = Gdiplus::Color(255, 140, 150, 160);
                    }

                    Gdiplus::Pen shieldPen(shieldColor, 2.5f);
                    graphics.DrawPath(&shieldPen, &shieldPath);

                    // Draw icon inside shield based on state
                    if (g_otpDialogState == OTPDialogState::SUCCESS) {
                        // Checkmark for success
                        Gdiplus::Pen checkPen(shieldColor, 3.5f);
                        checkPen.SetStartCap(Gdiplus::LineCapRound);
                        checkPen.SetEndCap(Gdiplus::LineCapRound);
                        checkPen.SetLineJoin(Gdiplus::LineJoinRound);
                        graphics.DrawLine(&checkPen, shieldCX - 12, shieldCY, shieldCX - 3, shieldCY + 10);
                        graphics.DrawLine(&checkPen, shieldCX - 3, shieldCY + 10, shieldCX + 14, shieldCY - 8);
                    } else if (g_otpDialogState == OTPDialogState::FAILURE) {
                        // X for failure
                        Gdiplus::Pen xPen(shieldColor, 3.5f);
                        xPen.SetStartCap(Gdiplus::LineCapRound);
                        xPen.SetEndCap(Gdiplus::LineCapRound);
                        graphics.DrawLine(&xPen, shieldCX - 10, shieldCY - 10, shieldCX + 10, shieldCY + 10);
                        graphics.DrawLine(&xPen, shieldCX + 10, shieldCY - 10, shieldCX - 10, shieldCY + 10);
                    } else {
                        // Key icon for input/verifying
                        Gdiplus::Pen keyPen(shieldColor, 2.5f);
                        keyPen.SetStartCap(Gdiplus::LineCapRound);
                        keyPen.SetEndCap(Gdiplus::LineCapRound);
                        // Key ring
                        graphics.DrawEllipse(&keyPen, shieldCX - 12, shieldCY - 12, 14, 14);
                        // Key shaft
                        graphics.DrawLine(&keyPen, shieldCX + 2, shieldCY + 2, shieldCX + 12, shieldCY + 12);
                        // Key teeth
                        graphics.DrawLine(&keyPen, shieldCX + 7, shieldCY + 7, shieldCX + 7, shieldCY + 11);
                        graphics.DrawLine(&keyPen, shieldCX + 10, shieldCY + 10, shieldCX + 10, shieldCY + 14);
                    }
                }
            }

            // Status text below the circle - changes based on state
            HFONT statusFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, statusFont);

            const wchar_t* statusText = L"P A S S C O D E";
            COLORREF statusColor = RGB(180, 180, 180);

            switch (g_otpDialogState) {
            case OTPDialogState::VERIFYING:
                statusText = L"V E R I F Y I N G";
                statusColor = RGB(196, 144, 68);
                break;
            case OTPDialogState::SUCCESS:
                statusText = L"A C C E S S   G R A N T E D";
                statusColor = RGB(103, 154, 65);
                break;
            case OTPDialogState::FAILURE:
                statusText = L"I N V A L I D   C O D E";
                statusColor = RGB(200, 80, 80);
                break;
            default:
                break;
            }

            SetTextColor(memDC, statusColor);
            RECT statusRect = {0, 258, OTP_DLG_WIDTH, 278};
            DrawTextW(memDC, statusText, -1, &statusRect, DT_CENTER | DT_SINGLELINE);

            // ===== CONTENT SECTION =====
            HFONT contentTitleFont = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, contentTitleFont);

            const wchar_t* titleText = L"Enter Passcode";
            const wchar_t* descText = L"Enter the 6-digit code from your\nWorldPosta Authenticator app";
            COLORREF titleColor = WP_DARK_BLUE;

            switch (g_otpDialogState) {
            case OTPDialogState::VERIFYING:
                titleText = L"Verifying Code";
                descText = L"Please wait while we verify\nyour passcode...";
                break;
            case OTPDialogState::SUCCESS:
                titleText = L"Verification Successful";
                descText = L"Your identity has been verified.\nYou will be signed in shortly.";
                titleColor = RGB(103, 154, 65);
                break;
            case OTPDialogState::FAILURE:
                titleText = L"Verification Failed";
                descText = L"The passcode was incorrect.\nPlease try again.";
                titleColor = RGB(200, 80, 80);
                break;
            default:
                break;
            }

            SetTextColor(memDC, titleColor);
            RECT contentTitleRect = {0, 290, OTP_DLG_WIDTH, 320};
            DrawTextW(memDC, titleText, -1, &contentTitleRect, DT_CENTER | DT_SINGLELINE);

            HFONT descFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, descFont);
            SetTextColor(memDC, WP_TEXT_GRAY);
            RECT descRect = {30, 325, OTP_DLG_WIDTH - 30, 370};
            DrawTextW(memDC, descText, -1, &descRect, DT_CENTER);

            // ===== INPUT SECTION ===== (only in INPUT state)
            if (g_otpDialogState == OTPDialogState::INPUT) {
                // Draw edit box border
                {
                    Gdiplus::Graphics graphics(memDC);
                    graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                    RECT editRect;
                    GetWindowRect(hEdit, &editRect);
                    MapWindowPoints(HWND_DESKTOP, hwnd, (LPPOINT)&editRect, 2);

                    Gdiplus::GraphicsPath editPath;
                    int r = 6;
                    int ex = editRect.left - 3, ey = editRect.top - 3;
                    int ew = editRect.right - editRect.left + 6, eh = editRect.bottom - editRect.top + 6;
                    editPath.AddArc(ex, ey, r*2, r*2, 180, 90);
                    editPath.AddArc(ex + ew - r*2, ey, r*2, r*2, 270, 90);
                    editPath.AddArc(ex + ew - r*2, ey + eh - r*2, r*2, r*2, 0, 90);
                    editPath.AddArc(ex, ey + eh - r*2, r*2, r*2, 90, 90);
                    editPath.CloseFigure();

                    Gdiplus::Pen borderPen(Gdiplus::Color(255, 200, 200, 200), 2);
                    graphics.DrawPath(&borderPen, &editPath);
                }

                // ===== VERIFY BUTTON =====
                {
                    Gdiplus::Graphics graphics(memDC);
                    graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                    Gdiplus::GraphicsPath verifyPath;
                    int r = 8;
                    verifyPath.AddArc(verifyButtonRect.left, verifyButtonRect.top, r*2, r*2, 180, 90);
                    verifyPath.AddArc(verifyButtonRect.right - r*2, verifyButtonRect.top, r*2, r*2, 270, 90);
                    verifyPath.AddArc(verifyButtonRect.right - r*2, verifyButtonRect.bottom - r*2, r*2, r*2, 0, 90);
                    verifyPath.AddArc(verifyButtonRect.left, verifyButtonRect.bottom - r*2, r*2, r*2, 90, 90);
                    verifyPath.CloseFigure();

                    Gdiplus::Color verifyColor = hoveredItem == 1 ? Gdiplus::Color(255, 85, 135, 55) : Gdiplus::Color(255, 103, 154, 65);
                    Gdiplus::SolidBrush verifyBrush(verifyColor);
                    graphics.FillPath(&verifyBrush, &verifyPath);

                    // Draw checkmark icon
                    int iconX = verifyButtonRect.left + 70;
                    int iconY = (verifyButtonRect.top + verifyButtonRect.bottom) / 2;
                    Gdiplus::Pen checkPen(Gdiplus::Color(255, 255, 255, 255), 2.0f);
                    checkPen.SetStartCap(Gdiplus::LineCapRound);
                    checkPen.SetEndCap(Gdiplus::LineCapRound);
                    graphics.DrawLine(&checkPen, iconX - 6, iconY, iconX - 2, iconY + 4);
                    graphics.DrawLine(&checkPen, iconX - 2, iconY + 4, iconX + 6, iconY - 4);

                    Gdiplus::FontFamily fontFamily(L"Segoe UI");
                    Gdiplus::Font btnFont(&fontFamily, 14, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                    Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255, 255));
                    Gdiplus::StringFormat sf;
                    sf.SetAlignment(Gdiplus::StringAlignmentCenter);
                    sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
                    Gdiplus::RectF verifyRectF((float)verifyButtonRect.left + 20, (float)verifyButtonRect.top,
                                               (float)(verifyButtonRect.right - verifyButtonRect.left) - 20,
                                               (float)(verifyButtonRect.bottom - verifyButtonRect.top));
                    graphics.DrawString(L"Verify Code", -1, &btnFont, verifyRectF, &sf, &whiteBrush);
                }

                // Cancel link
                {
                    Gdiplus::Graphics graphics(memDC);
                    graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                    int cancelCX = OTP_DLG_WIDTH / 2;
                    int cancelCY = cancelLinkRect.top + 8;
                    Gdiplus::Color cancelColor = hoveredItem == 2 ? Gdiplus::Color(255, 80, 80, 80) : Gdiplus::Color(255, 150, 150, 150);
                    Gdiplus::Pen circlePen(cancelColor, 1.2f);
                    graphics.DrawEllipse(&circlePen, cancelCX - 55, cancelCY - 6, 12, 12);
                    graphics.DrawLine(&circlePen, cancelCX - 52, cancelCY - 3, cancelCX - 46, cancelCY + 3);
                    graphics.DrawLine(&circlePen, cancelCX - 46, cancelCY - 3, cancelCX - 52, cancelCY + 3);

                    Gdiplus::FontFamily fontFamily(L"Segoe UI");
                    Gdiplus::Font cancelFontGdi(&fontFamily, 11, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                    Gdiplus::SolidBrush cancelBrush(cancelColor);
                    Gdiplus::StringFormat sf;
                    sf.SetAlignment(Gdiplus::StringAlignmentCenter);
                    sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
                    Gdiplus::RectF cancelRectF((float)cancelLinkRect.left + 15, (float)cancelLinkRect.top,
                                               (float)(cancelLinkRect.right - cancelLinkRect.left),
                                               (float)(cancelLinkRect.bottom - cancelLinkRect.top));
                    graphics.DrawString(L"CANCEL", -1, &cancelFontGdi, cancelRectF, &sf, &cancelBrush);
                }
            }
            // Show loading animation in VERIFYING state
            else if (g_otpDialogState == OTPDialogState::VERIFYING) {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                // Loading dots
                int dotY = 420;
                int dotRadius = 6;
                int dotSpacing = 25;
                int startX = OTP_DLG_WIDTH / 2 - dotSpacing;

                Gdiplus::SolidBrush dot1(Gdiplus::Color(255, 103, 154, 65));
                Gdiplus::SolidBrush dot2(Gdiplus::Color(150, 103, 154, 65));
                Gdiplus::SolidBrush dot3(Gdiplus::Color(80, 103, 154, 65));

                graphics.FillEllipse(&dot1, startX - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);
                graphics.FillEllipse(&dot2, startX + dotSpacing - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);
                graphics.FillEllipse(&dot3, startX + dotSpacing * 2 - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);
            }

            // ===== FOOTER =====
            RECT footerRect = {0, OTP_DLG_HEIGHT - 40, OTP_DLG_WIDTH, OTP_DLG_HEIGHT};
            HBRUSH footerBrush = CreateSolidBrush(WP_LIGHT_GRAY);
            FillRect(memDC, &footerRect, footerBrush);
            DeleteObject(footerBrush);

            HFONT footerFont = CreateFontW(10, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, footerFont);

            SetTextColor(memDC, WP_GREEN);
            RECT footerStatusRect = {20, OTP_DLG_HEIGHT - 28, 180, OTP_DLG_HEIGHT - 12};
            DrawTextW(memDC, L"\u25CF SECURE NODE ACTIVE", -1, &footerStatusRect, DT_LEFT | DT_SINGLELINE);

            SetTextColor(memDC, WP_TEXT_GRAY);
            RECT versionRect = {OTP_DLG_WIDTH - 100, OTP_DLG_HEIGHT - 28, OTP_DLG_WIDTH - 20, OTP_DLG_HEIGHT - 12};
            DrawTextW(memDC, L"WP-AUTH V1.0.0", -1, &versionRect, DT_RIGHT | DT_SINGLELINE);

            // Cleanup fonts
            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);
            DeleteObject(statusFont);
            DeleteObject(contentTitleFont);
            DeleteObject(descFont);
            DeleteObject(footerFont);

            BitBlt(hdc, 0, 0, OTP_DLG_WIDTH, OTP_DLG_HEIGHT, memDC, 0, 0, SRCCOPY);

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
            if (PtInRect(&verifyButtonRect, pt)) newHover = 1;
            else if (PtInRect(&cancelLinkRect, pt)) newHover = 2;

            if (newHover != hoveredItem) {
                hoveredItem = newHover;
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

            if (g_otpDialogState == OTPDialogState::INPUT) {
                if (PtInRect(&verifyButtonRect, pt)) {
                    // Get the entered code
                    wchar_t buffer[64] = {0};
                    GetWindowTextW(hEdit, buffer, 64);
                    enteredCode = buffer;

                    // Change to verifying state
                    g_otpDialogState = OTPDialogState::VERIFYING;
                    ShowWindow(hEdit, SW_HIDE);
                    InvalidateRect(hwnd, NULL, FALSE);

                    // Post message to trigger verification
                    PostMessage(hwnd, WM_OTP_RESULT, 0, 0);  // 0 = start verify
                } else if (PtInRect(&cancelLinkRect, pt)) {
                    g_otpResult = L"";
                    DestroyWindow(hwnd);
                }
            }
        }
        return 0;

    case WM_KEYDOWN:
        if (g_otpDialogState == OTPDialogState::INPUT) {
            if (wParam == VK_RETURN) {
                // Get the entered code
                wchar_t buffer[64] = {0};
                GetWindowTextW(hEdit, buffer, 64);
                enteredCode = buffer;

                // Change to verifying state
                g_otpDialogState = OTPDialogState::VERIFYING;
                ShowWindow(hEdit, SW_HIDE);
                InvalidateRect(hwnd, NULL, FALSE);

                // Post message to trigger verification
                PostMessage(hwnd, WM_OTP_RESULT, 0, 0);  // 0 = start verify
            } else if (wParam == VK_ESCAPE) {
                g_otpResult = L"";
                DestroyWindow(hwnd);
            }
        }
        return 0;

    case WM_OTP_RESULT:
        {
            // wParam: 0 = start verify, 1 = success, 2 = failure
            if (wParam == 0) {
                // Start verification - call the OTP callback if set
                if (g_otpVerifyCallback) {
                    std::wstring codeToVerify = enteredCode;
                    std::thread([hwnd, codeToVerify]() {
                        bool valid = g_otpVerifyCallback(codeToVerify);
                        if (IsWindow(hwnd)) {
                            PostMessage(hwnd, WM_OTP_RESULT, valid ? 1 : 2, 0);
                        }
                    }).detach();
                } else {
                    // No callback set - return the code immediately for external verification
                    // Don't show success/failure states - let the caller handle that
                    g_otpResult = enteredCode;
                    DestroyWindow(hwnd);
                }
            } else if (wParam == 1) {
                // OTP verified successfully
                g_otpResult = enteredCode;
                g_otpDialogState = OTPDialogState::SUCCESS;
                InvalidateRect(hwnd, NULL, FALSE);
                // Auto-close after 1.5 seconds
                SetTimer(hwnd, 2, 1500, NULL);
            } else {
                // OTP verification failed
                g_otpResult = L"";
                g_otpDialogState = OTPDialogState::FAILURE;
                InvalidateRect(hwnd, NULL, FALSE);
                // Auto-close after 2 seconds
                SetTimer(hwnd, 2, 2000, NULL);
            }
        }
        return 0;

    case WM_TIMER:
        if (wParam == 2) {
            KillTimer(hwnd, 2);
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_CLOSE:
        g_otpResult = L"";
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        g_otpDialogHwnd = NULL;
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
    g_otpDialogState = OTPDialogState::INPUT;

    HINSTANCE hInstance = GetModuleHandle(NULL);
    RegisterOTPDialogClass(hInstance);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int dlgWidth = 420;
    int dlgHeight = 580;
    int x = (screenWidth - dlgWidth) / 2;
    int y = (screenHeight - dlgHeight) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        WP_OTP_DIALOG_CLASS,
        L"WorldPosta Authenticator",
        WS_POPUP | WS_CAPTION | WS_VISIBLE,
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

// Push waiting dialog - New design matching main dialog
static LRESULT CALLBACK PushWaitingWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static RECT cancelLinkRect = {0};
    static int hoveredItem = 0;
    const int PUSH_DLG_WIDTH = 420;
    const int PUSH_DLG_HEIGHT = 450;

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();
            LoadLogoImage();
            cancelLinkRect = {PUSH_DLG_WIDTH/2 - 60, PUSH_DLG_HEIGHT - 50, PUSH_DLG_WIDTH/2 + 60, PUSH_DLG_HEIGHT - 25};
        }
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, PUSH_DLG_WIDTH, PUSH_DLG_HEIGHT);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            // Fill background with light gray
            RECT clientRect = {0, 0, PUSH_DLG_WIDTH, PUSH_DLG_HEIGHT};
            HBRUSH bgBrush = CreateSolidBrush(WP_LIGHT_GRAY2);
            FillRect(memDC, &clientRect, bgBrush);
            DeleteObject(bgBrush);

            SetBkMode(memDC, TRANSPARENT);

            // ===== HEADER SECTION =====
            if (g_logoImage != nullptr) {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
                graphics.DrawImage(g_logoImage, 25, 20, LOGO_SIZE, LOGO_SIZE);
            }

            // Title: "WorldPosta Authenticator"
            HFONT titleFont = CreateFontW(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, titleFont);
            SetTextColor(memDC, WP_DARK_BLUE);
            RECT titleRect = {85, 25, PUSH_DLG_WIDTH - 30, 50};
            DrawTextW(memDC, L"WorldPosta Authenticator", -1, &titleRect, DT_LEFT | DT_SINGLELINE);

            // Subtitle: "PUSH VERIFICATION"
            HFONT subtitleFont = CreateFontW(11, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, subtitleFont);
            SetTextColor(memDC, WP_GREEN);
            RECT subtitleRect = {85, 48, PUSH_DLG_WIDTH - 30, 65};
            DrawTextW(memDC, L"PUSH VERIFICATION", -1, &subtitleRect, DT_LEFT | DT_SINGLELINE);

            // WAITING badge (top right) - orange
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                Gdiplus::GraphicsPath badgePath;
                int badgeX = PUSH_DLG_WIDTH - 100, badgeY = 28, badgeW = 75, badgeH = 24;
                badgePath.AddArc(badgeX, badgeY, 12, 12, 180, 90);
                badgePath.AddArc(badgeX + badgeW - 12, badgeY, 12, 12, 270, 90);
                badgePath.AddArc(badgeX + badgeW - 12, badgeY + badgeH - 12, 12, 12, 0, 90);
                badgePath.AddArc(badgeX, badgeY + badgeH - 12, 12, 12, 90, 90);
                badgePath.CloseFigure();

                Gdiplus::SolidBrush badgeBrush(Gdiplus::Color(255, 255, 248, 230));
                graphics.FillPath(&badgeBrush, &badgePath);

                Gdiplus::SolidBrush orangeBrush(Gdiplus::Color(255, 196, 144, 68));
                graphics.FillEllipse(&orangeBrush, badgeX + 10, badgeY + 8, 8, 8);

                Gdiplus::FontFamily fontFamily(L"Segoe UI");
                Gdiplus::Font badgeFont(&fontFamily, 9, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::SolidBrush textBrush(Gdiplus::Color(255, 196, 144, 68));
                graphics.DrawString(L"WAITING", -1, &badgeFont, Gdiplus::PointF((float)badgeX + 22, (float)badgeY + 5), &textBrush);
            }

            // ===== PUSH ICON IN CIRCLE =====
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                int circleX = PUSH_DLG_WIDTH / 2;
                int circleY = 160;
                int circleRadius = 60;

                // Shadow
                Gdiplus::SolidBrush shadowBrush(Gdiplus::Color(30, 0, 0, 0));
                graphics.FillEllipse(&shadowBrush, circleX - circleRadius + 3, circleY - circleRadius + 3, circleRadius * 2, circleRadius * 2);

                // White circle
                Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255, 255));
                graphics.FillEllipse(&whiteBrush, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);

                // Draw push icon
                if (g_pushIconImage != nullptr) {
                    int iconSize = 60;
                    graphics.DrawImage(g_pushIconImage, circleX - iconSize/2, circleY - iconSize/2, iconSize, iconSize);
                }
            }

            // ===== CONTENT SECTION =====
            // "Waiting for Approval" title
            HFONT contentTitleFont = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, contentTitleFont);
            SetTextColor(memDC, WP_DARK_BLUE);
            RECT contentTitleRect = {0, 235, PUSH_DLG_WIDTH, 265};
            DrawTextW(memDC, L"Waiting for Approval", -1, &contentTitleRect, DT_CENTER | DT_SINGLELINE);

            // Description
            HFONT descFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, descFont);
            SetTextColor(memDC, WP_TEXT_GRAY);
            RECT descRect = {30, 275, PUSH_DLG_WIDTH - 30, 330};
            DrawTextW(memDC, L"A push notification has been sent to your\nmobile device. Please approve the request\nto continue.", -1, &descRect, DT_CENTER);

            // Loading spinner indicator (simple dots animation representation)
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                int dotY = 350;
                int dotRadius = 5;
                int dotSpacing = 20;
                int startX = PUSH_DLG_WIDTH / 2 - dotSpacing;

                Gdiplus::SolidBrush greenBrush(Gdiplus::Color(255, 103, 154, 65));
                Gdiplus::SolidBrush lightBrush(Gdiplus::Color(100, 103, 154, 65));

                graphics.FillEllipse(&greenBrush, startX - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);
                graphics.FillEllipse(&lightBrush, startX + dotSpacing - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);
                graphics.FillEllipse(&lightBrush, startX + dotSpacing * 2 - dotRadius, dotY - dotRadius, dotRadius * 2, dotRadius * 2);
            }

            // Cancel link
            HFONT cancelFont = CreateFontW(12, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, cancelFont);
            SetTextColor(memDC, hoveredItem == 1 ? RGB(80, 80, 80) : WP_TEXT_GRAY);
            DrawTextW(memDC, L"Cancel", -1, &cancelLinkRect, DT_CENTER | DT_SINGLELINE);

            // Cleanup fonts
            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);
            DeleteObject(subtitleFont);
            DeleteObject(contentTitleFont);
            DeleteObject(descFont);
            DeleteObject(cancelFont);

            BitBlt(hdc, 0, 0, PUSH_DLG_WIDTH, PUSH_DLG_HEIGHT, memDC, 0, 0, SRCCOPY);

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
            if (PtInRect(&cancelLinkRect, pt)) newHover = 1;

            if (newHover != hoveredItem) {
                hoveredItem = newHover;
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
            if (PtInRect(&cancelLinkRect, pt)) {
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
    int dlgWidth = 420;
    int dlgHeight = 450;
    int x = (screenWidth - dlgWidth) / 2;
    int y = (screenHeight - dlgHeight) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        WP_PUSH_WAITING_CLASS,
        L"WorldPosta Authenticator",
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

// Success dialog class and variables
static const wchar_t* WP_SUCCESS_DIALOG_CLASS = L"WorldPostaSuccessDialog";
static bool g_successClassRegistered = false;

// Success dialog window procedure - shows unlocked icon with green glow
static LRESULT CALLBACK SuccessDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static RECT okButtonRect = {0};
    const int SUCCESS_DLG_WIDTH = 420;
    const int SUCCESS_DLG_HEIGHT = 450;

    switch (msg) {
    case WM_CREATE:
        {
            InitGDIPlus();
            LoadLogoImage();

            // OK button position
            int btnWidth = 150;
            int btnHeight = 45;
            okButtonRect = {SUCCESS_DLG_WIDTH/2 - btnWidth/2, SUCCESS_DLG_HEIGHT - 80,
                           SUCCESS_DLG_WIDTH/2 + btnWidth/2, SUCCESS_DLG_HEIGHT - 80 + btnHeight};
        }
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, SUCCESS_DLG_WIDTH, SUCCESS_DLG_HEIGHT);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            // Fill background with light gray
            RECT clientRect = {0, 0, SUCCESS_DLG_WIDTH, SUCCESS_DLG_HEIGHT};
            HBRUSH bgBrush = CreateSolidBrush(WP_LIGHT_GRAY2);
            FillRect(memDC, &clientRect, bgBrush);
            DeleteObject(bgBrush);

            SetBkMode(memDC, TRANSPARENT);

            // ===== HEADER SECTION =====
            // Draw logo (small, top left)
            if (g_logoImage != nullptr) {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
                graphics.DrawImage(g_logoImage, 25, 20, LOGO_SIZE, LOGO_SIZE);
            }

            // Title: "WorldPosta Authenticator"
            HFONT titleFont = CreateFontW(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = (HFONT)SelectObject(memDC, titleFont);
            SetTextColor(memDC, WP_DARK_BLUE);
            RECT titleRect = {85, 25, SUCCESS_DLG_WIDTH - 30, 50};
            DrawTextW(memDC, L"WorldPosta Authenticator", -1, &titleRect, DT_LEFT | DT_SINGLELINE);

            // Subtitle: "IDENTITY VERIFIED"
            HFONT subtitleFont = CreateFontW(11, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, subtitleFont);
            SetTextColor(memDC, WP_GREEN);
            RECT subtitleRect = {85, 48, SUCCESS_DLG_WIDTH - 30, 65};
            DrawTextW(memDC, L"IDENTITY VERIFIED", -1, &subtitleRect, DT_LEFT | DT_SINGLELINE);

            // APPROVED badge (top right) - green
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                // Badge background (rounded rectangle) - green tint
                Gdiplus::GraphicsPath badgePath;
                int badgeX = SUCCESS_DLG_WIDTH - 110, badgeY = 28, badgeW = 85, badgeH = 24;
                badgePath.AddArc(badgeX, badgeY, 12, 12, 180, 90);
                badgePath.AddArc(badgeX + badgeW - 12, badgeY, 12, 12, 270, 90);
                badgePath.AddArc(badgeX + badgeW - 12, badgeY + badgeH - 12, 12, 12, 0, 90);
                badgePath.AddArc(badgeX, badgeY + badgeH - 12, 12, 12, 90, 90);
                badgePath.CloseFigure();

                Gdiplus::SolidBrush badgeBrush(Gdiplus::Color(255, 230, 255, 230));  // Light green
                graphics.FillPath(&badgeBrush, &badgePath);

                // Badge dot and text
                Gdiplus::SolidBrush greenBrush(Gdiplus::Color(255, 103, 154, 65));
                graphics.FillEllipse(&greenBrush, badgeX + 10, badgeY + 8, 8, 8);

                Gdiplus::FontFamily fontFamily(L"Segoe UI");
                Gdiplus::Font badgeFont(&fontFamily, 9, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::SolidBrush textBrush(Gdiplus::Color(255, 103, 154, 65));
                graphics.DrawString(L"APPROVED", -1, &badgeFont, Gdiplus::PointF((float)badgeX + 22, (float)badgeY + 5), &textBrush);
            }

            // ===== UNLOCKED ICON WITH GREEN GLOW =====
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                int circleX = SUCCESS_DLG_WIDTH / 2;
                int circleY = 170;
                int circleRadius = 70;

                // Green glow effect (multiple layers)
                for (int i = 4; i >= 0; i--) {
                    int glowRadius = circleRadius + 8 + i * 6;
                    int alpha = 20 - i * 4;
                    Gdiplus::SolidBrush glowBrush(Gdiplus::Color(alpha, 103, 154, 65));
                    graphics.FillEllipse(&glowBrush, circleX - glowRadius, circleY - glowRadius, glowRadius * 2, glowRadius * 2);
                }

                // White circle with green border
                Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255, 255));
                graphics.FillEllipse(&whiteBrush, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);

                Gdiplus::Pen greenPen(Gdiplus::Color(255, 103, 154, 65), 3);
                graphics.DrawEllipse(&greenPen, circleX - circleRadius, circleY - circleRadius, circleRadius * 2, circleRadius * 2);

                // Draw unlocked icon inside circle
                if (g_unlockedIconImage != nullptr) {
                    int iconSize = 70;
                    graphics.DrawImage(g_unlockedIconImage, circleX - iconSize/2, circleY - iconSize/2 - 5, iconSize, iconSize);
                }
            }

            // "UNLOCKED" text below the circle
            HFONT unlockedFont = CreateFontW(12, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, unlockedFont);
            SetTextColor(memDC, WP_GREEN);
            RECT unlockedRect = {0, 250, SUCCESS_DLG_WIDTH, 270};
            DrawTextW(memDC, L"UNLOCKED", -1, &unlockedRect, DT_CENTER | DT_SINGLELINE);

            // ===== ACCESS GRANTED SECTION =====
            // "Access Granted" title
            HFONT accessTitleFont = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, accessTitleFont);
            SetTextColor(memDC, WP_GREEN);
            RECT accessTitleRect = {0, 285, SUCCESS_DLG_WIDTH, 320};
            DrawTextW(memDC, L"Access Granted", -1, &accessTitleRect, DT_CENTER | DT_SINGLELINE);

            // Subtitle
            HFONT descFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            SelectObject(memDC, descFont);
            SetTextColor(memDC, WP_TEXT_GRAY);
            RECT descRect = {30, 325, SUCCESS_DLG_WIDTH - 30, 355};
            DrawTextW(memDC, L"Your identity has been verified successfully.", -1, &descRect, DT_CENTER | DT_SINGLELINE);

            // ===== OK BUTTON =====
            {
                Gdiplus::Graphics graphics(memDC);
                graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

                Gdiplus::GraphicsPath okPath;
                int r = 8;
                okPath.AddArc(okButtonRect.left, okButtonRect.top, r*2, r*2, 180, 90);
                okPath.AddArc(okButtonRect.right - r*2, okButtonRect.top, r*2, r*2, 270, 90);
                okPath.AddArc(okButtonRect.right - r*2, okButtonRect.bottom - r*2, r*2, r*2, 0, 90);
                okPath.AddArc(okButtonRect.left, okButtonRect.bottom - r*2, r*2, r*2, 90, 90);
                okPath.CloseFigure();

                Gdiplus::SolidBrush okBrush(Gdiplus::Color(255, 103, 154, 65));
                graphics.FillPath(&okBrush, &okPath);

                Gdiplus::FontFamily fontFamily(L"Segoe UI");
                Gdiplus::Font btnFont(&fontFamily, 14, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
                Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255, 255));
                Gdiplus::StringFormat sf;
                sf.SetAlignment(Gdiplus::StringAlignmentCenter);
                sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
                Gdiplus::RectF okRectF((float)okButtonRect.left, (float)okButtonRect.top,
                                       (float)(okButtonRect.right - okButtonRect.left),
                                       (float)(okButtonRect.bottom - okButtonRect.top));
                graphics.DrawString(L"Continue", -1, &btnFont, okRectF, &sf, &whiteBrush);
            }

            // Cleanup fonts
            SelectObject(memDC, oldFont);
            DeleteObject(titleFont);
            DeleteObject(subtitleFont);
            DeleteObject(unlockedFont);
            DeleteObject(accessTitleFont);
            DeleteObject(descFont);

            // Copy to screen
            BitBlt(hdc, 0, 0, SUCCESS_DLG_WIDTH, SUCCESS_DLG_HEIGHT, memDC, 0, 0, SRCCOPY);

            // Cleanup
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
                DestroyWindow(hwnd);
            }
        }
        return 0;

    case WM_KEYDOWN:
        if (wParam == VK_RETURN || wParam == VK_ESCAPE) {
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void RegisterSuccessDialogClass(HINSTANCE hInstance) {
    if (g_successClassRegistered) return;

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = SuccessDialogWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = WP_SUCCESS_DIALOG_CLASS;

    RegisterClassExW(&wc);
    g_successClassRegistered = true;
}

// Show custom success dialog with unlocked icon
static void ShowSuccessDialog(HWND parent) {
    HINSTANCE hInstance = GetModuleHandle(NULL);
    RegisterSuccessDialogClass(hInstance);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int dlgWidth = 420;
    int dlgHeight = 450;
    int x = (screenWidth - dlgWidth) / 2;
    int y = (screenHeight - dlgHeight) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        WP_SUCCESS_DIALOG_CLASS,
        L"Authentication Successful",
        WS_POPUP | WS_CAPTION | WS_VISIBLE,
        x, y, dlgWidth, dlgHeight,
        parent,
        NULL,
        hInstance,
        NULL
    );

    if (!hwnd) return;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void AuthDialog::ShowPushResultDialog(HWND parent, PushResult result) {
    if (result == PushResult::APPROVED) {
        // Show custom success dialog with unlocked icon
        ShowSuccessDialog(parent);
        return;
    }

    const wchar_t* title = L"WorldPosta Authentication";
    const wchar_t* message;
    UINT type;

    switch (result) {
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
