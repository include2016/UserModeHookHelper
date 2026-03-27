#pragma once
#include "pch.h"
#include <vector>
#include <string>

class CRemoveEarlyBreakDlg : public CDialogEx {
    DECLARE_DYNAMIC(CRemoveEarlyBreakDlg)

public:
    CRemoveEarlyBreakDlg(std::vector<std::wstring>& paths, CWnd* pParent = nullptr);
    virtual ~CRemoveEarlyBreakDlg();
    virtual BOOL OnInitDialog();
    afx_msg void OnOk();
    afx_msg void OnSize(UINT nType, int cx, int cy);
    
    std::vector<std::wstring>& m_paths;
    std::vector<int> m_selectedIndices;
    CListBox* m_pListBox;
    
    CListBox* GetListBox() { return m_pListBox; }
    
    DECLARE_MESSAGE_MAP()
};
