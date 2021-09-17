#include <Windows.h>
#include <stdio.h>

// éQçl
// ÅEMD4
// https://datatracker.ietf.org/doc/html/rfc1320

// íËêî
DWORD MD4_INITIAL_HASH[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

// ïœêî
DWORD64 MD4InBitsTotal;

DWORD WINAPI ROTL32(DWORD X, DWORD s)
{
	DWORD Ret;

	Ret = X << (s % 32) | X >> (32 - (s % 32));

	return Ret;
}

// MD4
DWORD WINAPI MD4F(DWORD X, DWORD Y, DWORD Z)
{
	DWORD Ret;

	Ret = (X & Y) | ((~X) & Z);

	return Ret;
}

DWORD WINAPI MD4G(DWORD X, DWORD Y, DWORD Z)
{
	DWORD Ret;

	Ret = (X & Y) | (X & Z) | (Y & Z);

	return Ret;
}

DWORD WINAPI MD4H(DWORD X, DWORD Y, DWORD Z)
{
	DWORD Ret;

	Ret = X ^ Y ^ Z;

	return Ret;
}

DWORD WINAPI MD4Round1(DWORD a, DWORD b, DWORD c, DWORD d, DWORD k, DWORD s, DWORD X[16])
{
	DWORD Ret;

	Ret = a + MD4F(b, c, d) + X[k];
	Ret = ROTL32(Ret, s);

	return Ret;
}

DWORD WINAPI MD4Round2(DWORD a, DWORD b, DWORD c, DWORD d, DWORD k, DWORD s, DWORD X[16])
{
	DWORD Ret;

	Ret = a + MD4G(b, c, d) + X[k] + 0x5A827999;
	Ret = ROTL32(Ret, s);

	return Ret;
}

DWORD WINAPI MD4Round3(DWORD a, DWORD b, DWORD c, DWORD d, DWORD k, DWORD s, DWORD X[16])
{
	DWORD Ret;

	Ret = a + MD4H(b, c, d) + X[k] + 0x6ED9EBA1;
	Ret = ROTL32(Ret, s);

	return Ret;
}

BOOL WINAPI MD4Update(BYTE M[64], BYTE ContextHash[16])
{
	DWORD X[16];
	DWORD j;
	DWORD A;
	DWORD B;
	DWORD C;
	DWORD D;
	DWORD AA;
	DWORD BB;
	DWORD CC;
	DWORD DD;

	A = (
		(((DWORD)(ContextHash[3]) << 24) & 0xFF000000) |
		(((DWORD)(ContextHash[2]) << 16) & 0x00FF0000) |
		(((DWORD)(ContextHash[1]) << 8) & 0x0000FF00) |
		(((DWORD)(ContextHash[0])) & 0x000000FF)
		);
	B = (
		(((DWORD)(ContextHash[7]) << 24) & 0xFF000000) |
		(((DWORD)(ContextHash[6]) << 16) & 0x00FF0000) |
		(((DWORD)(ContextHash[5]) << 8) & 0x0000FF00) |
		(((DWORD)(ContextHash[4])) & 0x000000FF)
		);
	C = (
		(((DWORD)(ContextHash[11]) << 24) & 0xFF000000) |
		(((DWORD)(ContextHash[10]) << 16) & 0x00FF0000) |
		(((DWORD)(ContextHash[9]) << 8) & 0x0000FF00) |
		(((DWORD)(ContextHash[8])) & 0x000000FF)
		);
	D = (
		(((DWORD)(ContextHash[15]) << 24) & 0xFF000000) |
		(((DWORD)(ContextHash[14]) << 16) & 0x00FF0000) |
		(((DWORD)(ContextHash[13]) << 8) & 0x0000FF00) |
		(((DWORD)(ContextHash[12])) & 0x000000FF)
		);

	AA = A;
	BB = B;
	CC = C;
	DD = D;

	for (j = 0; j < 16; j++)
	{
		X[j] = (
			(((DWORD)(M[j * 4 + 3]) << 24) & 0xFF000000) |
			(((DWORD)(M[j * 4 + 2]) << 16) & 0x00FF0000) |
			(((DWORD)(M[j * 4 + 1]) << 8) & 0x0000FF00) |
			(((DWORD)(M[j * 4])) & 0x000000FF)
			);
	}

	/* MD4 Round1 */
	A = MD4Round1(A, B, C, D, 0, 3, X);
	D = MD4Round1(D, A, B, C, 1, 7, X);
	C = MD4Round1(C, D, A, B, 2, 11, X);
	B = MD4Round1(B, C, D, A, 3, 19, X);

	A = MD4Round1(A, B, C, D, 4, 3, X);
	D = MD4Round1(D, A, B, C, 5, 7, X);
	C = MD4Round1(C, D, A, B, 6, 11, X);
	B = MD4Round1(B, C, D, A, 7, 19, X);

	A = MD4Round1(A, B, C, D, 8, 3, X);
	D = MD4Round1(D, A, B, C, 9, 7, X);
	C = MD4Round1(C, D, A, B, 10, 11, X);
	B = MD4Round1(B, C, D, A, 11, 19, X);

	A = MD4Round1(A, B, C, D, 12, 3, X);
	D = MD4Round1(D, A, B, C, 13, 7, X);
	C = MD4Round1(C, D, A, B, 14, 11, X);
	B = MD4Round1(B, C, D, A, 15, 19, X);

	/* MD4 Round2 */
	A = MD4Round2(A, B, C, D, 0, 3, X);
	D = MD4Round2(D, A, B, C, 4, 5, X);
	C = MD4Round2(C, D, A, B, 8, 9, X);
	B = MD4Round2(B, C, D, A, 12, 13, X);

	A = MD4Round2(A, B, C, D, 1, 3, X);
	D = MD4Round2(D, A, B, C, 5, 5, X);
	C = MD4Round2(C, D, A, B, 9, 9, X);
	B = MD4Round2(B, C, D, A, 13, 13, X);

	A = MD4Round2(A, B, C, D, 2, 3, X);
	D = MD4Round2(D, A, B, C, 6, 5, X);
	C = MD4Round2(C, D, A, B, 10, 9, X);
	B = MD4Round2(B, C, D, A, 14, 13, X);

	A = MD4Round2(A, B, C, D, 3, 3, X);
	D = MD4Round2(D, A, B, C, 7, 5, X);
	C = MD4Round2(C, D, A, B, 11, 9, X);
	B = MD4Round2(B, C, D, A, 15, 13, X);

	/* MD5 Round3 */
	A = MD4Round3(A, B, C, D, 0, 3, X);
	D = MD4Round3(D, A, B, C, 8, 9, X);
	C = MD4Round3(C, D, A, B, 4, 11, X);
	B = MD4Round3(B, C, D, A, 12, 15, X);

	A = MD4Round3(A, B, C, D, 2, 3, X);
	D = MD4Round3(D, A, B, C, 10, 9, X);
	C = MD4Round3(C, D, A, B, 6, 11, X);
	B = MD4Round3(B, C, D, A, 14, 15, X);

	A = MD4Round3(A, B, C, D, 1, 3, X);
	D = MD4Round3(D, A, B, C, 9, 9, X);
	C = MD4Round3(C, D, A, B, 5, 11, X);
	B = MD4Round3(B, C, D, A, 13, 15, X);

	A = MD4Round3(A, B, C, D, 3, 3, X);
	D = MD4Round3(D, A, B, C, 11, 9, X);
	C = MD4Round3(C, D, A, B, 7, 11, X);
	B = MD4Round3(B, C, D, A, 15, 15, X);

	A = A + AA;
	B = B + BB;
	C = C + CC;
	D = D + DD;

	*((DWORD*)&ContextHash[0]) = A;
	*((DWORD*)&ContextHash[4]) = B;
	*((DWORD*)&ContextHash[8]) = C;
	*((DWORD*)&ContextHash[12]) = D;

	return TRUE;
}

VOID WINAPI MD4(BYTE* in, DWORD64 cbitsIn, BOOL bInit, BOOL bFinish, BYTE* Hash) // BYTE Hash[16]
{
	BYTE i, M[64], HashCurrent[16];
	DWORD64 cbitsRemain, cbRemain, cbCurrent, * lpdw64;
	DWORD A, B, C, D, * lpdw;

	if (bInit)
	{
		// Step 3. Initialize MD Buffer
		A = MD4_INITIAL_HASH[0];
		B = MD4_INITIAL_HASH[1];
		C = MD4_INITIAL_HASH[2];
		D = MD4_INITIAL_HASH[3];

		lpdw = (DWORD*)HashCurrent;
		lpdw[0] = A;
		lpdw[1] = B;
		lpdw[2] = C;
		lpdw[3] = D;
		MD4InBitsTotal = 0;
	}
	else
	{
		memcpy(HashCurrent, Hash, sizeof(HashCurrent));
	}
	MD4InBitsTotal += cbitsIn;

	// Step 4. Process Message in 16-Word Blocks
	for (cbCurrent = 0, cbRemain = cbitsIn / 8; cbRemain >= sizeof(M); cbCurrent += sizeof(M), cbRemain -= sizeof(M))
	{
		MD4Update(&in[cbCurrent], HashCurrent);
	}

	if (bFinish)
	{
		lpdw64 = (DWORD64*)M;

		for (i = 0; i < 8; i++)
		{
			lpdw64[i] = 0;
		}

		// Step 1. Append Padding Bits
		cbitsRemain = cbitsIn % 512;
		cbRemain = cbitsRemain / 8;
		memcpy(M, &in[cbCurrent], cbRemain);
		cbCurrent += cbRemain;

		if ((cbitsRemain % 8) > 0)
		{
			M[cbRemain] = in[cbCurrent];
			M[cbRemain] |= ~(0x7f >> (cbitsRemain % 8));
		}
		else
		{
			M[cbRemain] = 0x80;
		}

		if (cbitsRemain >= 448)
		{
			MD4Update(M, HashCurrent);
			memset(M, 0, sizeof(M) - 8);
		}

		// Step 2. Append Length
		memcpy(&M[56], &MD4InBitsTotal, 8);

		MD4Update(M, HashCurrent);
	}

	// Step 5. Output
	memcpy(Hash, HashCurrent, sizeof(HashCurrent));

	return;
}

VOID WINAPI NTHash(LPSTR lpIn, BYTE* Hash) // BYTE Hash[16]
{
	DWORD cbIn, cchWideChars;
	WCHAR szWideChars[27];

	for (cbIn = 0; lpIn[cbIn] != '\0'; cbIn++) {}
	
	if (cbIn > 0x7fffffff)
	{
		return;
	}

	if (cbIn == 0)
	{
		MD4(NULL, 0, TRUE, TRUE, Hash);
	}
	else
	{
		// convert to unicode
		cchWideChars = (DWORD)MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpIn, cbIn, NULL, 0);
		if (cchWideChars != 0 && cchWideChars < 28)
		{
			cchWideChars = (DWORD)MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpIn, cbIn, szWideChars, cchWideChars);
			MD4((BYTE*)szWideChars, (DWORD64)cchWideChars * 8 * 2, TRUE, TRUE, Hash);
		}
	}

	return;
}

VOID WINAPI CrackNTHash(BYTE* Hash, CHAR* szPassword, LPDWORD lpcbPassword)
{

	return;
}

INT main(INT argc, CHAR* argv[])
{
	// test suite:
	// NTHash("") = 31d6cfe0d16ae931b73c59d7e0c089c0
	// NTHash("P@ssw0rd") = e19ccf75ee54e06b06a5907af13cef42

	CHAR szPassword[] = "";// "P@ssw0rd";
	BYTE Hash[16];

	NTHash(szPassword, Hash);

	return 0;
}