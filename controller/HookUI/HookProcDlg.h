// HookProcDlg.h - MFC dialog definition for per-process hook UI.
#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <string>
#include <afxwin.h>        // core MFC (CWnd, etc.)
#include <afxdialogex.h>   // CDialogEx definition
#include <afxcmn.h>        // common controls (CListCtrl)
#include "HookInterfaces.h"
#include "HookUIResource.h"
#include "../../Shared/HookRow.h"
#include "../../Shared/HookServices.h"
#include <unordered_map>
#include "../../Shared/HookServices.h"
#include "DllLoadMonManager.h"

class HookProcDlg : public CDialogEx {
public:
    HookProcDlg(DWORD pid, const std::wstring& name, IHookServices* services, CWnd* parent=nullptr);
    BOOL CreateModeless(CWnd* parent);
    static const UINT kMsgHookDlgDestroyed;
protected:
	afx_msg bool HookCommonCode(DWORD64 module_base, DWORD module_offset, std::wstring hook_code_path, std::wstring export_func_name);
    virtual BOOL OnInitDialog();
    virtual void DoDataExchange(CDataExchange* pDX) { CDialogEx::DoDataExchange(pDX);}    
    afx_msg void OnDestroy();
    afx_msg void OnBnClickedApplyHook();
    afx_msg void OnBnClickedApplyHookSequence();
    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
    afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
    afx_msg void OnMouseMove(UINT nFlags, CPoint point);
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* lpMMI);
    afx_msg void OnColumnClickModules(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnModuleItemChanged(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnEnSetFocusOffset();
    afx_msg void OnEnSetFocusDirect();
    afx_msg void OnCustomDrawModules(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnContextMenu(CWnd* pWnd, CPoint point);
    afx_msg void OnHookMenuDisable();
    afx_msg void OnHookMenuEnable();
    afx_msg void OnHookMenuRemove();
    DECLARE_MESSAGE_MAP()
private:
    void PopulateModuleList();
    bool GetSelectedModule(std::wstring& name, ULONGLONG& base) const;
    ULONGLONG ParseAddressText(const std::wstring& text, bool& ok) const;
    void FreeModuleRows();
    void FreeHookRows();
    struct ModuleRow { ULONGLONG base; ULONGLONG size; std::wstring name; std::wstring path; };
    DWORD m_pid; std::wstring m_name; IHookServices* m_services=nullptr; CListCtrl m_ModuleList;
    CListCtrl m_HookList;
    int m_splitPos = 250;
    bool m_draggingSplitter = false;
    int m_splitterWidth = 6;
    void UpdateLayoutForSplitter(int cx, int cy);
    int m_sortColumn=0; bool m_sortAscending=true; static int CALLBACK ModuleCompare(LPARAM, LPARAM, LPARAM);
    // Delay Hook 相关数据结构和成员
    struct PendingHookKey {
        DWORD pid;
        std::wstring moduleName;
        bool operator==(const PendingHookKey& other) const {
            return pid == other.pid && moduleName == other.moduleName;
        }
    };
    
    struct PendingHookKeyHash {
        size_t operator()(const PendingHookKey& k) const noexcept {
            return std::hash<DWORD>()(k.pid) ^ std::hash<std::wstring>()(k.moduleName);
        }
    };
    
    // Pending hooks 存储
    std::unordered_map<PendingHookKey, std::vector<PendingHook>, PendingHookKeyHash> m_PendingHooks;
    
    // DllLoadMon manager for delayed hooking
    DllLoadMonManager m_DllLoadMonMgr;
    
    // 监控线程参数
    struct MonitorParams {
        DWORD processId;
        HANDLE hProcess;
        HANDLE hEventLoad;
        HANDLE hEventRelease;
        std::wstring moduleName;
        HookProcDlg* pDlg;  // 指向对话框实例
    };
    
    // 延迟钩子监控线程
    static DWORD WINAPI DelayHookMonitorThread(LPVOID lpParam);
    
    // 辅助函数声明
    void ApplyPendingHooks(DWORD pid, const std::wstring& moduleName);
    bool ApplySinglePendingHook(const PendingHook& hook);
    
    // 原有成员
    void PopulateHookList();
    int AddHookEntry(const HookRow& row);
	ULONG64 m_exp_num_tracker_bitfield[4] = {};

};
