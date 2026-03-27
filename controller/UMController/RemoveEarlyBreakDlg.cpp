#include "pch.h"
#include "RemoveEarlyBreakDlg.h"
#include "Resource.h"
#include "Helper.h"

IMPLEMENT_DYNAMIC(CRemoveEarlyBreakDlg, CDialogEx)

CRemoveEarlyBreakDlg::CRemoveEarlyBreakDlg(std::vector<std::wstring>& paths, CWnd* pParent)
    : CDialogEx(IDD_REMOVE_HOOK_DLG, pParent), m_paths(paths), m_pListBox(nullptr) {
}

CRemoveEarlyBreakDlg::~CRemoveEarlyBreakDlg() {}

BEGIN_MESSAGE_MAP(CRemoveEarlyBreakDlg, CDialogEx)
    ON_COMMAND(IDOK, &CRemoveEarlyBreakDlg::OnOk)
    ON_WM_SIZE()
END_MESSAGE_MAP()

BOOL CRemoveEarlyBreakDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    SetWindowText(L"Remove from EarlyBreak List");
    
    m_pListBox = (CListBox*)GetDlgItem(IDC_LIST_PROC);
    if (!m_pListBox) return TRUE;
    
    int maxPixel = 0;
    CDC* pDC = m_pListBox->GetDC();
    for (const auto &p : m_paths) {
        std::wstring display = p.empty() ? L"(unknown)" : p;
        m_pListBox->AddString(display.c_str());
        if (pDC) {
            CSize sz = pDC->GetTextExtent(display.c_str());
            if (sz.cx > maxPixel) maxPixel = sz.cx;
        }
    }
    if (pDC) m_pListBox->ReleaseDC(pDC);
    // Add some padding so long paths don't truncate immediately at edge
    if (maxPixel > 0) m_pListBox->SetHorizontalExtent(maxPixel + 20);
    
    return TRUE;
}

void CRemoveEarlyBreakDlg::OnOk() {
    if (!m_pListBox) { EndDialog(IDCANCEL); return; }
    int count = m_pListBox->GetCount();
    m_selectedIndices.clear();
    for (int i = 0; i < count; ++i) {
        if (m_pListBox->GetSel(i) > 0) m_selectedIndices.push_back(i);
    }
    if (m_selectedIndices.empty()) { EndDialog(IDCANCEL); return; }
    
    EndDialog(IDOK);
}

void CRemoveEarlyBreakDlg::OnSize(UINT nType, int cx, int cy) {
    CDialogEx::OnSize(nType, cx, cy);
    // Resize list box to fill most of client area and reposition buttons at bottom-right
    if (!m_pListBox) return;
    CWnd* okBtn = GetDlgItem(IDOK);
    CWnd* cancelBtn = GetDlgItem(IDCANCEL);
    if (!okBtn || !cancelBtn) return;
    const int margin = 7;
    const int buttonHeight = 18;
    const int buttonWidth = 80;
    int listBottom = cy - margin - buttonHeight - 8; // leave space for buttons
    if (listBottom < 60) listBottom = 60;
    m_pListBox->MoveWindow(margin, 20, cx - 2*margin, listBottom - 20);
    int btnY = cy - margin - buttonHeight;
    cancelBtn->MoveWindow(cx - margin - buttonWidth, btnY, buttonWidth, buttonHeight);
    okBtn->MoveWindow(cx - margin - 2*buttonWidth - 8, btnY, buttonWidth, buttonHeight);
}
