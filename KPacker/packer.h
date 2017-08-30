#pragma once
#include "stdafx.h"


class Packer
{
public:
	Packer() {fileBuf = NULL;}
	DWORD RVA2RAW(DWORD rva)
	{
		if(is32)
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS32			INH32;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			DWORD ret = 0;
			for(int i=0; i<INH32->FileHeader.NumberOfSections; i++)
			{
				if(firstSection[i].VirtualAddress <= rva && rva < firstSection[i].VirtualAddress + firstSection[i].Misc.VirtualSize)
				{ // ���ϴ� rva �� ���ϴ� VA �� i��° ���ǿ� �����ִٸ�
					ret = rva - firstSection[i].VirtualAddress + firstSection[i].PointerToRawData;
					return ret;
				}
			}
		}
		else
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS64			INH64;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH64 = (PIMAGE_NT_HEADERS64)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH64->OptionalHeader) + INH64->FileHeader.SizeOfOptionalHeader);
			DWORD ret = 0;
			for(int i=0; i<INH64->FileHeader.NumberOfSections; i++)
			{
				if(firstSection[i].VirtualAddress <= rva && rva < firstSection[i].VirtualAddress + firstSection[i].Misc.VirtualSize)
				{ // ���ϴ� rva �� ���ϴ� VA �� i��° ���ǿ� �����ִٸ�
					ret = rva - firstSection[i].VirtualAddress + firstSection[i].PointerToRawData;
					return ret;
				}
			}
		}
		return 0;
	}
	DWORD RAW2RVA(DWORD raw)
	{
		if(is32)
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS32			INH32;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			DWORD ret = 0;
			for(int i=0; i<INH32->FileHeader.NumberOfSections; i++)
			{
				if(firstSection[i].PointerToRawData <= raw && raw < firstSection[i].PointerToRawData + firstSection[i].SizeOfRawData)
				{ // ���ϴ� raw �� ���ϴ� rawpointer �� i ��° ���ǿ� �����ִٸ�
					ret = raw + firstSection[i].VirtualAddress - firstSection[i].PointerToRawData;
					return ret;
				}
			}
		}else
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS64			INH64;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH64 = (PIMAGE_NT_HEADERS64)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH64->OptionalHeader) + INH64->FileHeader.SizeOfOptionalHeader);
			DWORD ret = 0;
			for(int i=0; i<INH64->FileHeader.NumberOfSections; i++)
			{
				if(firstSection[i].PointerToRawData <= raw && raw < firstSection[i].PointerToRawData + firstSection[i].SizeOfRawData)
				{ // ���ϴ� raw �� ���ϴ� rawpointer �� i ��° ���ǿ� �����ִٸ�
					ret = raw + firstSection[i].VirtualAddress - firstSection[i].PointerToRawData;
					return ret;
				}
			}
		}
		return 0;
	}
	bool packing(const string& filepath)
	{
		if(	initBuf(filepath.c_str()) == true)
		{
			removeASLR();
			if(!is32)
				return false;
			addSection();
			copyToKsoo();
			writeToMinyong();
			setImportPtr();
			encryptor();
			insertUnpack();
			wrtieToFile();
			return true;
		}
		else
		{
			return false;
		}
	}
	bool initBuf(const char* filepath){
		// ���۸���� ������ �޸𸮿� �ø��� �Լ�
		if(fileBuf)
			delete [] fileBuf;
		fin.close();
		fin.open(filepath, ifstream::binary);
		if(fin.good() == false)
			return false;
		string result_file_name = filepath;
		result_file_name.erase(result_file_name.end()-4, result_file_name.end());
		//result_file_name[result_file_name.size()-4] = '\0';
		result_file_name += "_packed.exe";
		fout.open(result_file_name, ofstream::binary);
		if(fout.good() == false)
			return false;
		fin.seekg(0,ifstream::end);
		fileSize=fin.tellg();

		fileBuf = new BYTE[fileSize + 0x3000];// �˳��ϰ� 
		memset(fileBuf, 0, fileSize + 0x3000); // �� ������ �ϴ� 0���� ä��
		fin.seekg(0, ifstream::beg);
		fin.read((char*)fileBuf, fileSize); // �� �б�
		return true;
	}
	void removeASLR()
	{
		// ASLR ����.
		PIMAGE_NT_HEADERS32			INH32;
		PIMAGE_NT_HEADERS64			INH64;
		PIMAGE_DOS_HEADER			IDH;
		IDH = (PIMAGE_DOS_HEADER)fileBuf;
		INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
		INH64 = (PIMAGE_NT_HEADERS64)(fileBuf + IDH->e_lfanew);
		if(INH32->FileHeader.SizeOfOptionalHeader == 0xE0) // 32 bit
		{
			is32 = TRUE;
		}
		else
		{
			is32 = FALSE;
		}

		if(is32)
		{
			INH32->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED; // �Ӽ��߰�
			INH32->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE; // �Ӽ�����
		}
		else
		{
			INH64->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED; // �Ӽ��߰�
			INH64->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE; // �Ӽ�����
		}
	}
	void addSection()
	{
		PIMAGE_DOS_HEADER			IDH;
		PIMAGE_NT_HEADERS32			INH32;
		PIMAGE_NT_HEADERS64			INH64;
		PIMAGE_SECTION_HEADER		ISH, ISH_ksoo, ISH_minyong;
		PIMAGE_IMPORT_DESCRIPTOR	IDT;
		IDH = (PIMAGE_DOS_HEADER)fileBuf;
		INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
		INH64 = (PIMAGE_NT_HEADERS64)(fileBuf + IDH->e_lfanew);
		

		if(is32)
		{
			WORD NumberOfSections = INH32->FileHeader.NumberOfSections;
			DWORD SectionAlignment = INH32->OptionalHeader.SectionAlignment;
			DWORD FileAlignment = INH32->OptionalHeader.FileAlignment;
			oep = INH32->OptionalHeader.AddressOfEntryPoint;
			ISH = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);

			// Bount Import Table ����. BIT �� �δ��� IAT ä��� ���ؼ� �ִ°���. ������.
			INH32->OptionalHeader.DataDirectory[0xB].VirtualAddress = INH32->OptionalHeader.DataDirectory[0xB].Size = 0x0;
			if((DWORD)(ISH + (INH32->FileHeader.NumberOfSections+1)) - (DWORD)fileBuf + sizeof(IMAGE_SECTION_HEADER) >= ISH->PointerToRawData) 
			{ // �ش� ������ ���ڶ�� �ڷ� ��.
				auto ishtemp = ISH;
				for(int i=0; i<INH32->FileHeader.NumberOfSections; i++)
					(ishtemp++)->PointerToRawData += FileAlignment;
				for(DWORD i = fileSize; i >= INH32->OptionalHeader.SizeOfHeaders; i--)
				{
					fileBuf[i + FileAlignment] = fileBuf[i];
					fileBuf[i] = 0;
				}
				INH32->OptionalHeader.SizeOfHeaders += FileAlignment;
			}

			//.ksoo �� .minyong �߰�.
			PIMAGE_SECTION_HEADER newISH1, newISH2, lastSection;
			lastSection = ISH + (INH32->FileHeader.NumberOfSections-1);
			newISH1 = ISH + INH32->FileHeader.NumberOfSections;
			newISH2 = newISH1 + 1;
			newISH1->Name[0] = '.';newISH1->Name[1] = 'k';newISH1->Name[2] = 's';newISH1->Name[3] = 'o';newISH1->Name[4] = 'o';
			newISH1->Name[5] = '\0';newISH1->Name[6] = '\0';newISH1->Name[7] = '\0';
			newISH2->Name[0] = '.';newISH2->Name[1] = 'm';newISH2->Name[2] = 'i';newISH2->Name[3] = 'n';newISH2->Name[4] = 'y';
			newISH2->Name[5] = 'o';newISH2->Name[6] = 'n';newISH2->Name[7] = 'g';
			newISH1->Misc.VirtualSize = (int)(0x1000 / SectionAlignment) * SectionAlignment; 
			newISH2->Misc.VirtualSize = (int)(0x1000 / SectionAlignment) * SectionAlignment;
			//newISH1->VirtualAddress = lastSection->VirtualAddress + lastSection->Misc.VirtualSize;
			//newISH1->VirtualAddress += (SectionAlignment - (newISH1->VirtualAddress % SectionAlignment))%SectionAlignment;
			newISH1->VirtualAddress = (ceil((double(lastSection->VirtualAddress + lastSection->Misc.VirtualSize))/(double)SectionAlignment)) * SectionAlignment;
			//newISH2->VirtualAddress = newISH1->VirtualAddress + newISH1->Misc.VirtualSize;
			//newISH2->VirtualAddress += (SectionAlignment - (newISH2->VirtualAddress % SectionAlignment))%SectionAlignment;
			newISH2->VirtualAddress = (ceil((double(newISH1->VirtualAddress + newISH1->Misc.VirtualSize))/(double)SectionAlignment)) * SectionAlignment;
			//IMAGE_SECTION_HEADER
			newISH1->SizeOfRawData = (0x1000 / FileAlignment) * FileAlignment;
			newISH2->SizeOfRawData = (0x1000 / FileAlignment) * FileAlignment;
			/*if(FileAlignment >= 0x400)
			{
				newISH1->SizeOfRawData = FileAlignment; newISH2->SizeOfRawData = FileAlignment;
			}
			else
			{
				newISH1->SizeOfRawData = newISH2->SizeOfRawData = (0x400 / FileAlignment) * FileAlignment;
				if(0x400 % FileAlignment)
				{
					newISH1->SizeOfRawData += FileAlignment;
					newISH2->SizeOfRawData += FileAlignment;
				}
			}*/
			newISH1->PointerToRawData = (ceil((double)(lastSection->PointerToRawData + lastSection->SizeOfRawData)/(double)FileAlignment)) * FileAlignment;
			newISH2->PointerToRawData = (ceil((double)(newISH1->PointerToRawData + newISH1->SizeOfRawData)/(double)FileAlignment)) * FileAlignment;
			

			/*newISH1->PointerToRawData = lastSection->PointerToRawData + lastSection->SizeOfRawData;
			newISH1->PointerToRawData += (FileAlignment - (newISH1->PointerToRawData % FileAlignment))%FileAlignment;
			newISH2->PointerToRawData = newISH1->PointerToRawData + newISH1->SizeOfRawData;
			newISH2->PointerToRawData += (FileAlignment - (newISH2->PointerToRawData % FileAlignment))%FileAlignment;*/
			newISH1->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
			newISH2->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
			
			INH32->FileHeader.NumberOfSections += 2;
			memset((void*)(fileBuf + newISH1->PointerToRawData), 0xCDCDCDCD, newISH1->SizeOfRawData);
			memset((void*)(fileBuf + newISH2->PointerToRawData), 0xCFCFCFCF, newISH2->SizeOfRawData);
			INH32->OptionalHeader.SizeOfImage = newISH2->VirtualAddress + newISH2->Misc.VirtualSize;
		}
		else
		{
			
		}
	}
	void copyToKsoo()
	{   // Import Address Table �� ksoo �� ������.
		if(is32)
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS32			INH32;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			ksooSection = firstSection + (INH32->FileHeader.NumberOfSections - 2);
			minySection = firstSection + (INH32->FileHeader.NumberOfSections - 1);
			WORD NumberOfSections = INH32->FileHeader.NumberOfSections;

			PIMAGE_SECTION_HEADER ISH = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			
			// import address table �� ksoo �� �ű�.
			{
				BYTE* srcPtr = fileBuf;
				srcPtr += RVA2RAW(INH32->OptionalHeader.DataDirectory[1].VirtualAddress);
				BYTE* destPtr = fileBuf;
				destPtr += ksooSection->PointerToRawData; // ksoo section �� ����Ʈ ����.
				while(1)
				{
					memcpy(destPtr, srcPtr, sizeof(DWORD)*5); // IMAGE_IMPORT_DESCRIPTOR ����ü �迭�� ���� �ּ�
					destPtr += sizeof(DWORD)*5;

					DWORD a,b,c,d,e;
					a = *(DWORD*)srcPtr;
					srcPtr += 4;
					b = *(DWORD*)srcPtr;
					srcPtr += 4;
					c = *(DWORD*)srcPtr;
					srcPtr += 4;
					d = *(DWORD*)srcPtr;
					srcPtr += 4;
					e = *(DWORD*)srcPtr;
					srcPtr += 4;

					if(a == 0 && b == 0 && c == 0 && d == 0 && e == 0)
						break;
				}
				// 
				DWORD endOfImport = (destPtr - fileBuf)  - ksooSection->PointerToRawData + ksooSection->VirtualAddress + INH32->OptionalHeader.ImageBase;
				destPtr = fileBuf + ksooSection->PointerToRawData;
				destPtr += 0x300;

				DWORD temp = INH32->OptionalHeader.DataDirectory[1].VirtualAddress + INH32->OptionalHeader.ImageBase;
				memcpy(destPtr, &temp, sizeof(DWORD)); // +0x300 ��ġ�� ��������� ImageBase ����. ImportTables �� ��.
				destPtr += sizeof(DWORD);

				temp = ksooSection->VirtualAddress + INH32->OptionalHeader.ImageBase;
				memcpy(destPtr, &temp, sizeof(DWORD)); // +0x304 ��ġ�� ksooSection ������ġ.
				destPtr += sizeof(DWORD);

				memcpy(destPtr, &endOfImport,  sizeof(DWORD)); // +0x308 ��ġ��. ksooSection �� import ��ġ ��.
				destPtr += sizeof(DWORD);

				DWORD sz = endOfImport - temp;
				memcpy(destPtr, &sz, sizeof(DWORD)); // +0x30C ��ġ�� import table �� ũ�⸦ ����. (���� ���Ҵµ� �Ⱦ���)
				destPtr += sizeof(DWORD); 

				memcpy(destPtr, &INH32->OptionalHeader.ImageBase, sizeof(DWORD)); // ImageBase �����س� +0x310 ��ġ��.
				destPtr += sizeof(DWORD);

				auto ishp = firstSection;
				DWORD n = NumberOfSections - 2;
				memcpy(destPtr, &n, sizeof(DWORD)); // ��ȣȭ�� ���ǰ��� ����. +0x314 ��ġ��.
				destPtr += sizeof(DWORD);

				// ��ȣȭ�� ������ ksoo ����(+0x318 ��ġ����)��  ǥ����
				// 01 401000 401055 00 402000 402143 ... �̷������� ������.
				// 01 �� ��ȣȭ �ؾߵǴ� �����̰� 00 �̸� ��ȣȭ ���ϴ� ����.
				for(int i=0; i<NumberOfSections - 2; i++, ishp++) 
				{
					DWORD a,b;
					a = INH32->OptionalHeader.ImageBase + ishp->VirtualAddress;
					b = a + ishp->SizeOfRawData;
					
					BOOL notEnc = FALSE;
					for(unsigned int dirIndex = 0; dirIndex <= 0xF; dirIndex++)
					{ // �ϳ��� ���ԵǸ� notEnc = TRUE ���� ��ȣȭ �ȵǰ� �Ѵ�.
						DWORD c = INH32->OptionalHeader.DataDirectory[dirIndex].VirtualAddress + INH32->OptionalHeader.ImageBase;
						if(a<=c && c<b)
						{
							notEnc = TRUE;
							break;
						}
					}
					if(notEnc)
					{
						BYTE isEnc = 0x00; // RVA �� DirectoryData �� ���ԵǸ� ��ȣȭ ���� �ʴ´�.
						memcpy(destPtr, &isEnc, sizeof(BYTE));
						destPtr += sizeof(BYTE);
					}
					else
					{
						BYTE isEnc = 0x01; 
						memcpy(destPtr, &isEnc, sizeof(BYTE));
						destPtr += sizeof(BYTE);
					}

					memcpy(destPtr, &a, sizeof(DWORD));
					destPtr += sizeof(DWORD);

					memcpy(destPtr, &b, sizeof(DWORD));
					destPtr += sizeof(DWORD);
				}
			}
		}
		else
		{ // 64Bit
			
		}
	}

	void writeToMinyong()
	{
		// packing �ڵ忡�� ���� �Լ�(LoadLibrary, GetProcAddress, ExitProcess)�� Import Table �� �����ϴ� �Լ�.
		// ExitProcess �� ���� �� �˾Ҵµ�, �Ⱦ��� ��.
		if(is32)
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS32			INH32;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			ksooSection = firstSection + (INH32->FileHeader.NumberOfSections - 2);
			minySection = firstSection + (INH32->FileHeader.NumberOfSections - 1);
			
			BYTE* destPtr = fileBuf;
			destPtr += minySection->PointerToRawData;
			strcpy((char*)destPtr, "kernel32.dll");
			destPtr += strlen("kernel32.dll") + 1;

			DWORD hintNameRaw = destPtr - fileBuf + sizeof(DWORD)*4;
			DWORD hintNameRVA = RAW2RVA(hintNameRaw);
			memcpy((char*)destPtr, &hintNameRVA, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			hintNameRaw += strlen("LoadLibraryA") + 1 + sizeof(WORD); // hint �� WORD ��������.
			hintNameRVA = RAW2RVA(hintNameRaw);
			memcpy((char*)destPtr, &hintNameRVA, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			hintNameRaw += strlen("GetProcAddress") + 1 + sizeof(WORD); // hint �� WORD ��������.
			hintNameRVA = RAW2RVA(hintNameRaw);
			memcpy((char*)destPtr, &hintNameRVA, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			DWORD ddummy = 0;
			memcpy((char*)destPtr, &ddummy, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			WORD wdummy = 0;
			memcpy((char*)destPtr, &wdummy, sizeof(WORD));
			destPtr += sizeof(WORD);

			strcpy((char*)destPtr, "LoadLibraryA");
			destPtr += strlen("LoadLibraryA") + 1;

			memcpy((char*)destPtr, &wdummy, sizeof(WORD));
			destPtr += sizeof(WORD);

			strcpy((char*)destPtr, "GetProcAddress");
			destPtr += strlen("GetProcAddress") + 1;

			memcpy((char*)destPtr, &wdummy, sizeof(WORD));
			destPtr += sizeof(WORD);

			strcpy((char*)destPtr, "ExitProcess");
			destPtr += strlen("ExitProcess") + 1;

			// Entry Point �� ���� �߰��� �������� ����.
			INH32->OptionalHeader.AddressOfEntryPoint = RAW2RVA(destPtr - fileBuf); 
			while(0);
		}
		else
		{
		}
	}
	void setImportPtr()
	{
		if(is32)
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS32			INH32;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			ksooSection = firstSection + (INH32->FileHeader.NumberOfSections - 2);
			minySection = firstSection + (INH32->FileHeader.NumberOfSections - 1);

			BYTE* destPtr = fileBuf;
			destPtr += RVA2RAW(INH32->OptionalHeader.DataDirectory[1].VirtualAddress);

			DWORD temp = 0;

			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			temp = minySection->VirtualAddress;
			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			//temp += sizeof(DWORD)*4 + sizeof(WORD)*(strlen("LoadLibraryA") + 1 + strlen("GetProcAddress") + 1 + strlen("ExitProcess") + 1);
			temp += strlen("kernel32.dll") + 1; // .minyong �� "kernel32.dll" \0 �ٷ� ���� ��ġ.
			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			temp = 0;

			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);

			memcpy(destPtr, &temp, sizeof(DWORD));
			destPtr += sizeof(DWORD);
		}
		else
		{ // 64bit.
		}
	}
	void encryptor()
	{
		if(is32)
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS32			INH32;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			ksooSection = firstSection + (INH32->FileHeader.NumberOfSections - 2);
			minySection = firstSection + (INH32->FileHeader.NumberOfSections - 1);
			WORD NumberOfSections = INH32->FileHeader.NumberOfSections;

			auto ishp = firstSection;
			for(int i=0; i<NumberOfSections - 2; i++, ishp++) // ksoo, minyong ���� �����ϰ� ��ȣȭ
			{
				for(DWORD fileoffset = ishp->PointerToRawData; fileoffset < ishp->PointerToRawData + ishp->SizeOfRawData; fileoffset++)
				{
					DWORD a = RAW2RVA(ishp->PointerToRawData);
					DWORD b = RAW2RVA(ishp->PointerToRawData + ishp->SizeOfRawData);

					BOOL notEnc = FALSE;
					for(unsigned int dirIndex = 0x0; dirIndex <= 0xF; dirIndex++)
					{
						if(a<=INH32->OptionalHeader.DataDirectory[dirIndex].VirtualAddress && 
						INH32->OptionalHeader.DataDirectory[dirIndex].VirtualAddress < b)
						{
							notEnc = TRUE;
							break;
						}
					}
					if(notEnc)
						break;
					
					
					fileBuf[fileoffset] = fileBuf[fileoffset] ^ 0x10;
				}
			}
		}
		else
		{ // 64bit
		}
	}
	void insertUnpack()
	{
		if(is32)
		{
			PIMAGE_SECTION_HEADER		firstSection, ksooSection, minySection;
			PIMAGE_NT_HEADERS32			INH32;
			PIMAGE_DOS_HEADER			IDH;
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
			firstSection = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			ksooSection = firstSection + (INH32->FileHeader.NumberOfSections - 2);
			minySection = firstSection + (INH32->FileHeader.NumberOfSections - 1);
			DWORD imageBase = INH32->OptionalHeader.ImageBase;

			DWORD dwLoadLibrary, dwGetProcAddress, dwExitProcess;
			dwLoadLibrary = imageBase + minySection->VirtualAddress + 0xD;
			dwGetProcAddress = imageBase + minySection->VirtualAddress + 0x11;
			dwExitProcess = imageBase + minySection->VirtualAddress + 0x15;
			
			BYTE* destPtr = fileBuf;
			destPtr += RVA2RAW(minySection->VirtualAddress);
			
			//destPtr ���� minyong Section �κ�.
			{
				destPtr += 0x900;
				DWORD jmpadd = 0; // ���� ������ �پ�ߵ�.
				BYTE codes[] = {0xE9};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));
				destPtr = insertOpCode(destPtr, &jmpadd, sizeof(jmpadd));
			}

			destPtr = fileBuf; // �� ����
			destPtr += RVA2RAW(INH32->OptionalHeader.AddressOfEntryPoint);
			{	BYTE codes[] = {0x60,0x55,0x8B,0xEC,0x81,0xC4,0x44,0xFF,0xFF,0xFF};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	BYTE codes[] = {0x6A,0x00,0x68,0x2E,0x64,0x6C,0x6C,0x68,0x65,0x6C,0x33,0x32,0x68,0x6B,0x65,0x72,0x6E,0x54,0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwLoadLibrary, sizeof(dwLoadLibrary));	}
			{	BYTE codes[] = {0x89,0x45,0x8C,0x68,0x63,0x74,0x00,0x00,0x68,0x72,0x6F,0x74,0x65,0x68,0x75,0x61,0x6C,0x50,0x68,0x56,0x69,0x72,0x74,0x54,0xFF,0x75,0x8C,0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwGetProcAddress, sizeof(dwGetProcAddress));	}
			{	BYTE codes[] = {0x89,0x45,0xE8,0x68,0x61,0x72,0x79,0x00,0x68,0x4C,0x69,0x62,0x72,0x68,0x46,0x72,0x65,0x65,0x54,0xFF,0x75,0x8C,0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwGetProcAddress, sizeof(dwGetProcAddress));	}
			{	BYTE codes[] = {0x89,0x45,0xE0,0x6A,0x00,0x68,0x72,0x65,0x61,0x64,0x68,0x74,0x65,0x54,0x68,0x68,0x43,0x72,0x65,0x61,0x54,0xFF,0x75,0x8C,0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwGetProcAddress, sizeof(dwGetProcAddress));	}
			{	BYTE codes[] = {0x89,0x45,0xE4,0x6A,0x00,0x6A,0x00,0x6A,0x00,0x68};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + minySection->VirtualAddress + 0x900;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			//-----------------------------
			{	BYTE codes[] = {0x6A,0x00,0x6A,0x00,0xFF,0x55,0xE4,0xC7,0x45,0xFC,0x00,0x00,0x00,0x00,0xBE};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x314;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			{	BYTE codes[] = {0x8B,0x06,0x89,0x45,0xFC,0x83,0xC6,0x04,0x33,0xC9,0xEB,0x7E,0x51,0xB8,0x09,0x00,0x00,0x00,0xF7,0xE1,0x03,0xC6,0xEB,0x01,0x00,0x8B,0x00,0x88,0x85,0x5F,0xFF,0xFF,0xFF,0xB8,0x09,0x00,0x00,0x00,0xF7,0xE1,0x03,0xC6,0x40,0xEB,0x01,0x0C,0xEB,0x01,0x00,0x8B,0x00,0x89,0x45,0xF8,0xB8,0x09,0x00,0x00,0x00,0xF7,0xE1,0x03,0xC6,0x83,0xC0,0x05,0x8B,0x00,0x89,0x45,0xF4,0xB8,0x04,0x00,0x00,0x00,0xF7,0xE1,0x8D,0x55,0x90,0x03,0xD0,0x52,0x6A,0x04,0xEB,0x01,0x00,0x8B,0x45,0xF8,0x8B,0x5D,0xF4,0x8B,0xD3,0x2B,0xD0,0x52,0x50,0xFF,0x55,0xE8,0x8B,0x45,0xF8,0x8B,0x5D,0xF4,0x80,0xBD,0x5F,0xFF,0xFF,0xFF,0x00,0x74,0x11,0xEB,0x0B,0x8A,0x10,0xEB,0x01,0x00,0x80,0xF2,0x10,0x88,0x10,0x40,0x3B,0xC3,0x75,0xF1,0x59,0x41,0x3B,0x4D,0xFC,0x0F,0x82,0x79,0xFF,0xFF,0xFF,0xA1};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x304;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}

			{	BYTE codes[] = {0x8B,0x1D};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x308;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}

			{	BYTE codes[] = {0x33,0xC9,0xEB,0x13,0x8A,0x10,0xBF};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x300;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			
			{	BYTE codes[] = {0x90,0x8B,0x3F,0x03,0xF9,0xEB,0x01,0x00,0x88,0x17,0x40,0x41,0x3B,0xC3,0x75,0xE9,0x8B,0x35};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x300;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			
			{	BYTE codes[] = {0x89,0xB5,0x70,0xFF,0xFF,0xFF,0x8B,0xB5,0x70,0xFF,0xFF,0xFF,0x8B,0x16,0x0B,0xD2,0x74,0x02,0xEB,0x29,0x8B,0x56,0x04,0x0B,0xD2,0x74,0x02,0xEB,0x20,0x8B,0x56,0x08,0x0B,0xD2,0x74,0x02,0xEB,0x17,0x8B,0x56,0x0C,0x0B,0xD2,0x74,0x02,0xEB,0x0E,0x8B,0x56,0x10,0x0B,0xD2,0x74,0x02,0xEB,0x05,0xE9,0x15,0x01,0x00,0x00,0x50,0x64,0xA1,0x18,0x00,0x00,0x00,0x89,0x85,0x44,0xFF,0xFF,0xFF,0x58,0x8D,0x46,0x0C,0x8B,0x00,0x03,0x05};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x310;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			{	BYTE codes[] = {0x50,0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwLoadLibrary, sizeof(dwGetProcAddress));	}
			{	BYTE codes[] = {0x89,0x85,0x64,0xFF,0xFF,0xFF,0x8B,0x06,0x50,0x8B,0x85,0x44,0xFF,0xFF,0xFF,0x8B,0x40,0x30,0x89,0x85,0x44,0xFF,0xFF,0xFF,0x58,0x03,0x05};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x310;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			{	BYTE codes[] = {0x89,0x85,0x6C,0xFF,0xFF,0xFF,0x8D,0x46,0x10,0x50,0x8B,0x85,0x44,0xFF,0xFF,0xFF,0x0F,0xB6,0x40,0x02,0x89,0x85,0x44,0xFF,0xFF,0xFF,0x58,0x8B,0x00,0x03,0x05};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x310;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			{	BYTE codes[] = {0x89,0x85,0x68,0xFF,0xFF,0xFF,0x83,0xBD,0x44,0xFF,0xFF,0xFF,0x00,0x74,0x06,0x33,0xC0,0x89,0x18,0xFF,0xE0,0x8B,0xB5,0x6C,0xFF,0xFF,0xFF,0xEB,0x01,0x00,0x8B,0x16,0x0B,0xD2,0x75,0x06,0x8B,0xB5,0x68,0xFF,0xFF,0xFF,0x8B,0x16,0x0B,0xD2,0x75,0x02,0xEB,0x6D,0x81,0xFA,0x00,0x00,0x00,0x80,0x73,0x22,0x8B,0x16,0x03,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x310;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			{	BYTE codes[] = {0x83,0xC2,0x02,0x52,0xFF,0xB5,0x64,0xFF,0xFF,0xFF,0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwGetProcAddress, sizeof(dwGetProcAddress));	}
			{	BYTE codes[] = {0x8B,0xBD,0x68,0xFF,0xFF,0xFF,0x89,0x07,0xEB,0x20,0x8B,0xF2,0x81,0xE6,0xFF,0xFF,0x00,0x00,0xEB,0x01,0x00,0x56,0xFF,0xB5,0x64,0xFF,0xFF,0xFF, 0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwGetProcAddress, sizeof(dwGetProcAddress));	}
			{	BYTE codes[] = {0x8B,0xBD,0x68,0xFF,0xFF,0xFF,0x89,0x07,0x8B,0x95,0x6C,0xFF,0xFF,0xFF,0x83,0xC2,0x04,0x89,0x95,0x6C,0xFF,0xFF,0xFF,0x8B,0x95,0x68, 0xFF,0xFF,0xFF,0x83,0xC2,0x04,0x89,0x95,0x68,0xFF,0xFF,0xFF,0xE9,0x76,0xFF,0xFF,0xFF,0x8B,0xB5,0x70,0xFF,0xFF,0xFF,0x83,0xC6,0x14,0x89,0xB5,0x70,0xFF,0xFF,0xFF, 0xE9,0xB4,0xFE,0xFF,0xFF,0xC7,0x45,0xFC,0x00,0x00,0x00,0x00,0xBE};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	DWORD dummy = imageBase + ksooSection->VirtualAddress + 0x314;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}
			{	BYTE codes[] = {0xEB,0x01,0x79,0x8B,0x06,0x89,0x45,0xFC,0x83,0xC6,0x04,0x33,0xC9,0xE9,0x81
,0x00,0x00,0x00,0x51,0xB8,0x09,0x00,0x00,0x00,0xF7,0xE1,0x03,0xC6,0x40,0x50,0x64,0xA1,0x18,0x00,0x00,0x00,0x89,0x85,0x44,0xFF,0xFF,0xFF,0x58,0x8B,0x00,0x89,0x45
,0xF8,0xB8,0x09,0x00,0x00,0x00,0xF7,0xE1,0x03,0xC6,0x50,0x8B,0x85,0x44,0xFF,0xFF,0xFF,0x8B,0x40,0x30,0x89,0x85,0x44,0xFF,0xFF,0xFF,0x58,0x83,0xC0,0x05,0xEB,0x01
,0x79,0x8B,0x00,0x89,0x45,0xF4,0x8D,0x85,0x60,0xFF,0xFF,0xFF,0x50,0x8B,0x85,0x44,0xFF,0xFF,0xFF,0x0F,0xB6,0x40,0x02,0x89,0x85,0x44,0xFF,0xFF,0xFF,0x58,0x50,0x8B
,0x44,0x8D,0x90,0x50,0x8B,0x45,0xF8,0x8B,0x5D,0xF4,0x8B,0xD3,0x83,0xBD,0x44,0xFF,0xFF,0xFF,0x00,0x74,0x06,0x33,0xC0,0x89,0x18,0xFF,0xE0,0x2B,0xD0,0x52,0x50,0xFF
,0x55,0xE8,0x59,0x41,0x3B,0x4D,0xFC,0x0F,0x82,0x76,0xFF,0xFF,0xFF,0xC9,0x61};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			//NNNNNNNNNNNNNNNNNNNNNNNN
			{	DWORD currentAddress = RAW2RVA(destPtr - fileBuf);
				BYTE codes[] = {0xE9}; // 
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));
				DWORD dummy = this->oep  - currentAddress - 5;
				destPtr = insertOpCode(destPtr, &dummy, sizeof(dummy));		}

			
			destPtr = fileBuf;
			destPtr += RVA2RAW(minySection->VirtualAddress);

			//destPtr ���� minyong Section �κ�.

			//INH32->OptionalHeader.DataDirectory[1].VirtualAddress, 
			//ksooSection->VirtualAddress
			destPtr += 0x905;
			{	BYTE codes[] = {0x55,0x8B,0xEC,0x83,0xC4,0xF4,0x6A,0x00,0x68,0x2E,0x64,0x6C,0x6C,0x68,0x65,0x6C,0x33,0x32,0x68,0x6B,0x65,0x72,0x6E,0x54,0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwLoadLibrary, sizeof(dwLoadLibrary));	}

			{	BYTE codes[] = {0x89,0x45,0xF8,0x6A,0x70,0x68,0x53,0x6C,0x65,0x65,0x54,0xFF,0x75,0xF8,0xFF,0x15};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
			{	destPtr = insertOpCode(destPtr, &dwGetProcAddress, sizeof(dwGetProcAddress));	}

			{	BYTE codes[] = {0x89,0x45,0xFC,0x50,0x64,0xA1,0x18,0x00,0x00,0x00,0x89,0x45,0xF4,0x58,0xEB,0x01,0x00,0x50,0x8B,0x45,0xF4,0x8B,0x40,0x30,0xEB,0x01,0x0C,0x89,0x45,0xF4,0x58,0x50,0x8B,0x45,0xF4,0x0F,0xB6,0x40,0x02,0x89,0x45,0xF4,0x58,0xEB,0x01,0x0C, 0x83,0x7D,0xF4,0x00,0x74,0x0F,0xEB,0x01,0x0C,0xEB,0x01,0x0C,0xEB,0x01,0x0C,0x33,0xC0,0x89,0x18,0xFF,0xE0,0x68,0x88,0x13,0x00,0x00,0xFF,0x55,0xFC,0xEB,0xB6,0xC9,0xC2,0x04,0x00};
				destPtr = insertOpCode(destPtr, codes, sizeof(codes));		}
		}
		else
		{ // 64bit
		}
	}
	void wrtieToFile()
	{
		if(is32)
		{
			PIMAGE_SECTION_HEADER		ISH;
			PIMAGE_NT_HEADERS32			INH32;
			PIMAGE_DOS_HEADER			IDH;
			PIMAGE_SECTION_HEADER lastSection;
			//////////////////////////////////////
			IDH = (PIMAGE_DOS_HEADER)fileBuf;
			INH32 = (PIMAGE_NT_HEADERS32)(fileBuf + IDH->e_lfanew);
			ISH = (PIMAGE_SECTION_HEADER)((DWORD)(&INH32->OptionalHeader) + INH32->FileHeader.SizeOfOptionalHeader);
			lastSection = ISH + (INH32->FileHeader.NumberOfSections - 1);
			

			
			fout.write((const char*)fileBuf, lastSection->PointerToRawData + lastSection->SizeOfRawData);
			fout.clear();
			fout.close();
			fin.close();
		}
		else
		{ // 64bit.

		}
	}
	
	

	

	
private:
	BYTE* insertOpCode(const BYTE* dest, void* codes, unsigned int codesize)
	{
		//BYTE codes[] = {0x50};
		memcpy((void*)dest, codes, codesize);
		return (BYTE*)dest + codesize;
	}


public:
	BOOL is32;
	ifstream fin;
private:
	ofstream fout;
	BYTE* fileBuf;
	DWORD fileSize;
	
	DWORD oep;
};


/*

405500 �� ���� hmod ���� 
405504 �� VirtualProtect ���� 
405508 �� FreeLibrary ���� 
40550C �� OldProperties ���� 
405510 �� �������� ���� hmod ���� 
405514 �� wholeptr 
405518 �� INTptr 
40551C �� IATptr 
405520 �� subINTptr 
405524 �� subIATptr 

404300 �� DataDirectory[1].VirtualAddress + ImageBase ����          -(importTables)
404304 �� ksooSection ������ġ										-�����ؾߵ� �ڵ�...���� ��
404308 �� ksooSection ��.											-�����ؾߵ� �ڵ�...���� ��
40430C �� Import Table �� ũ�� 
404310 �� ImageBase �� 
404314 �� ��ȣȭ�� ������ ����										-(encSections)
404318 ���� ��ȣȭ�� ������ ����(voff)��ġ�� OverOfEnd �� �����
404400 �� OEP ����.													-OEP
40500D - LoadLibrary
405011 - GetProcAddress
*/