
// KPacker.h : PROJECT_NAME ���� ���α׷��� ���� �� ��� �����Դϴ�.
//

#pragma once
#include "stdafx.h"
#ifndef __AFXWIN_H__
	#error "PCH�� ���� �� ������ �����ϱ� ���� 'stdafx.h'�� �����մϴ�."
#endif

#include "resource.h"		// �� ��ȣ�Դϴ�.


// CKPackerApp:
// �� Ŭ������ ������ ���ؼ��� KPacker.cpp�� �����Ͻʽÿ�.
//

class CKPackerApp : public CWinApp
{
public:
	CKPackerApp();

// �������Դϴ�.
public:
	virtual BOOL InitInstance();

// �����Դϴ�.

	DECLARE_MESSAGE_MAP()
};

extern CKPackerApp theApp;