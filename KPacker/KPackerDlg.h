
// KPackerDlg.h : ��� ����
//

#pragma once
#include "stdafx.h"
#include "packer.h"

// CKPackerDlg ��ȭ ����
class CKPackerDlg : public CDialogEx
{
// �����Դϴ�.
public:
	CKPackerDlg(CWnd* pParent = NULL);	// ǥ�� �������Դϴ�.

// ��ȭ ���� �������Դϴ�.
	enum { IDD = IDD_KPACKER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV �����Դϴ�.


// �����Դϴ�.
protected:
	HICON m_hIcon;

	// ������ �޽��� �� �Լ�
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
private:
	Packer packer;
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
public:
	afx_msg void OnDropFiles(HDROP hDropInfo);
};
