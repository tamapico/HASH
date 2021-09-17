#include <Windows.h>
#include <stdio.h>

// 参考
// ・MD4
// https://datatracker.ietf.org/doc/html/rfc1320
// 
// ・MD5
// http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf
// http://www.ietf.org/rfc/rfc1321.txt
// 
// ・SHA1, SHA224, SHA256, SHA384, SHA512
// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
// http://www.rfc-editor.org/rfc/rfc4634.txt
// http://www.rfc-editor.org/rfc/rfc6234.txt

// 定数
DWORD MD5_T[64] =
{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391

};

DWORD SHA1_K[80] =
{
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
};

DWORD SHA224_256_K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

DWORD64 SHA384_512_K[80] =
{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

DWORD MD4_INITIAL_HASH[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

DWORD MD5_INITIAL_HASH[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

DWORD SHA1_INITIAL_HASH[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

DWORD SHA224_INITIAL_HASH[8] = { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };

DWORD SHA256_INITIAL_HASH[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

DWORD64 SHA384_INITIAL_HASH[8] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4 };

DWORD64 SHA512_INITIAL_HASH[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

// 変数
DWORD64 MD4InBitsTotal;
DWORD64 MD5InBitsTotal;
DWORD64 SHA1InBitsTotal;
DWORD64 SHA224InBitsTotal;
DWORD64 SHA256InBitsTotal;
DWORD64 SHA284InBitsTotal;
DWORD64 SHA512InBitsTotal;

// 関数

DWORD WINAPI ROTL32(DWORD X, DWORD s)
{
	DWORD Ret;

	Ret = X << (s % 32) | X >> (32 - (s % 32));

	return Ret;
}

DWORD WINAPI ROTR32(DWORD X, DWORD s)
{
	DWORD Ret;

	Ret = X >> (s % 32) | X << (32 - (s % 32));

	return Ret;
}

DWORD64 WINAPI ROTL64(DWORD64 X, DWORD s)
{
	DWORD64 Ret;

	Ret = X << (s % 64) | X >> (64 - (s % 64));

	return Ret;
}

DWORD64 WINAPI ROTR64(DWORD64 X, DWORD s)
{
	DWORD64 Ret;

	Ret = X >> (s % 64) | X << (64 - (s % 64));

	return Ret;
}

DWORD WINAPI SHR32(DWORD X, DWORD s)
{
	DWORD Ret;

	Ret = X >> s;

	return Ret;
}

DWORD64 WINAPI SHR64(DWORD64 X, DWORD s)
{
	DWORD64 Ret;

	Ret = X >> s;

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

// MD5

DWORD WINAPI MD5F(DWORD X, DWORD Y, DWORD Z)
{
	DWORD Ret;

	Ret = X & Y | ~X & Z;

	return Ret;
}

DWORD WINAPI MD5G(DWORD X, DWORD Y, DWORD Z)
{
	DWORD Ret;

	Ret = X & Z | Y & ~Z;

	return Ret;
}

DWORD WINAPI MD5H(DWORD X, DWORD Y, DWORD Z)
{
	DWORD Ret;

	Ret = X ^ Y ^ Z;

	return Ret;
}

DWORD WINAPI MD5I(DWORD X, DWORD Y, DWORD Z)
{
	DWORD Ret;

	Ret = Y ^ (X | ~Z);

	return Ret;
}

DWORD WINAPI MD5Round1(DWORD a, DWORD b, DWORD c, DWORD d, DWORD k, DWORD s, DWORD i, DWORD X[16])
{
	DWORD Ret;

	Ret = a + MD5F(b, c, d) + X[k] + MD5_T[i - 1];
	Ret = ROTL32(Ret, s) + b;

	return Ret;
}

DWORD WINAPI MD5Round2(DWORD a, DWORD b, DWORD c, DWORD d, DWORD k, DWORD s, DWORD i, DWORD X[16])
{
	DWORD Ret;

	Ret = a + MD5G(b, c, d) + X[k] + MD5_T[i - 1];
	Ret = ROTL32(Ret, s) + b;

	return Ret;
}

DWORD WINAPI MD5Round3(DWORD a, DWORD b, DWORD c, DWORD d, DWORD k, DWORD s, DWORD i, DWORD X[16])
{
	DWORD Ret;

	Ret = a + MD5H(b, c, d) + X[k] + MD5_T[i - 1];
	Ret = ROTL32(Ret, s) + b;

	return Ret;
}

DWORD WINAPI MD5Round4(DWORD a, DWORD b, DWORD c, DWORD d, DWORD k, DWORD s, DWORD i, DWORD X[16])
{
	DWORD Ret;

	Ret = a + MD5I(b, c, d) + X[k] + MD5_T[i - 1];
	Ret = ROTL32(Ret, s) + b;

	return Ret;
}

BOOL WINAPI MD5Update(BYTE M[64], BYTE ContextHash[16])
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

	/* MD5 Round1 */
	A = MD5Round1(A, B, C, D, 0, 7, 1, X);
	D = MD5Round1(D, A, B, C, 1, 12, 2, X);
	C = MD5Round1(C, D, A, B, 2, 17, 3, X);
	B = MD5Round1(B, C, D, A, 3, 22, 4, X);

	A = MD5Round1(A, B, C, D, 4, 7, 5, X);
	D = MD5Round1(D, A, B, C, 5, 12, 6, X);
	C = MD5Round1(C, D, A, B, 6, 17, 7, X);
	B = MD5Round1(B, C, D, A, 7, 22, 8, X);

	A = MD5Round1(A, B, C, D, 8, 7, 9, X);
	D = MD5Round1(D, A, B, C, 9, 12, 10, X);
	C = MD5Round1(C, D, A, B, 10, 17, 11, X);
	B = MD5Round1(B, C, D, A, 11, 22, 12, X);

	A = MD5Round1(A, B, C, D, 12, 7, 13, X);
	D = MD5Round1(D, A, B, C, 13, 12, 14, X);
	C = MD5Round1(C, D, A, B, 14, 17, 15, X);
	B = MD5Round1(B, C, D, A, 15, 22, 16, X);

	/* MD5 Round2 */
	A = MD5Round2(A, B, C, D, 1, 5, 17, X);
	D = MD5Round2(D, A, B, C, 6, 9, 18, X);
	C = MD5Round2(C, D, A, B, 11, 14, 19, X);
	B = MD5Round2(B, C, D, A, 0, 20, 20, X);

	A = MD5Round2(A, B, C, D, 5, 5, 21, X);
	D = MD5Round2(D, A, B, C, 10, 9, 22, X);
	C = MD5Round2(C, D, A, B, 15, 14, 23, X);
	B = MD5Round2(B, C, D, A, 4, 20, 24, X);

	A = MD5Round2(A, B, C, D, 9, 5, 25, X);
	D = MD5Round2(D, A, B, C, 14, 9, 26, X);
	C = MD5Round2(C, D, A, B, 3, 14, 27, X);
	B = MD5Round2(B, C, D, A, 8, 20, 28, X);

	A = MD5Round2(A, B, C, D, 13, 5, 29, X);
	D = MD5Round2(D, A, B, C, 2, 9, 30, X);
	C = MD5Round2(C, D, A, B, 7, 14, 31, X);
	B = MD5Round2(B, C, D, A, 12, 20, 32, X);

	/* MD5 Round3 */
	A = MD5Round3(A, B, C, D, 5, 4, 33, X);
	D = MD5Round3(D, A, B, C, 8, 11, 34, X);
	C = MD5Round3(C, D, A, B, 11, 16, 35, X);
	B = MD5Round3(B, C, D, A, 14, 23, 36, X);

	A = MD5Round3(A, B, C, D, 1, 4, 37, X);
	D = MD5Round3(D, A, B, C, 4, 11, 38, X);
	C = MD5Round3(C, D, A, B, 7, 16, 39, X);
	B = MD5Round3(B, C, D, A, 10, 23, 40, X);

	A = MD5Round3(A, B, C, D, 13, 4, 41, X);
	D = MD5Round3(D, A, B, C, 0, 11, 42, X);
	C = MD5Round3(C, D, A, B, 3, 16, 43, X);
	B = MD5Round3(B, C, D, A, 6, 23, 44, X);

	A = MD5Round3(A, B, C, D, 9, 4, 45, X);
	D = MD5Round3(D, A, B, C, 12, 11, 46, X);
	C = MD5Round3(C, D, A, B, 15, 16, 47, X);
	B = MD5Round3(B, C, D, A, 2, 23, 48, X);

	/* MD5 Round4 */
	A = MD5Round4(A, B, C, D, 0, 6, 49, X);
	D = MD5Round4(D, A, B, C, 7, 10, 50, X);
	C = MD5Round4(C, D, A, B, 14, 15, 51, X);
	B = MD5Round4(B, C, D, A, 5, 21, 52, X);

	A = MD5Round4(A, B, C, D, 12, 6, 53, X);
	D = MD5Round4(D, A, B, C, 3, 10, 54, X);
	C = MD5Round4(C, D, A, B, 10, 15, 55, X);
	B = MD5Round4(B, C, D, A, 1, 21, 56, X);

	A = MD5Round4(A, B, C, D, 8, 6, 57, X);
	D = MD5Round4(D, A, B, C, 15, 10, 58, X);
	C = MD5Round4(C, D, A, B, 6, 15, 59, X);
	B = MD5Round4(B, C, D, A, 13, 21, 60, X);

	A = MD5Round4(A, B, C, D, 4, 6, 61, X);
	D = MD5Round4(D, A, B, C, 11, 10, 62, X);
	C = MD5Round4(C, D, A, B, 2, 15, 63, X);
	B = MD5Round4(B, C, D, A, 9, 21, 64, X);

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

// MD5 によるハッシュ作成
// in ... 入力データ
// cbitsIn ... 入力データのビット数
// bInit ... 最初の入力かどうか
// bFinish ... 最後の入力かどうか
// Hash ... 計算されたハッシュ
// ・入力されるメッセージの合計は 0～2^64 - 1ビット
// ・一度の入力で完了する場合、bInit と bFinish は両方 TRUE
// ・何度かに分割して入力する場合、最初と途中の入力は 512 ビット (64 バイト) の倍数である必要がある
// 　また最初の入力は bInit = TRUE, bFinish = FALSE 、途中の入力は bInit = FALSE, bFinish = FALSE、
// 　最後の入力は bInit = FALSE, bFinish = TRUE とする
VOID WINAPI MD5(BYTE* in, DWORD64 cbitsIn, BOOL bInit, BOOL bFinish, BYTE* Hash) // BYTE Hash[16]
{
	BYTE i, M[64], HashCurrent[16];
	DWORD64 cbitsRemain, cbRemain, cbCurrent, * lpdw64;
	DWORD A, B, C, D, * lpdw;

	if (bInit)
	{
		// Step 3. Initialize MD Buffer
		A = MD5_INITIAL_HASH[0];
		B = MD5_INITIAL_HASH[1];
		C = MD5_INITIAL_HASH[2];
		D = MD5_INITIAL_HASH[3];

		lpdw = (DWORD*)HashCurrent;
		lpdw[0] = A;
		lpdw[1] = B;
		lpdw[2] = C;
		lpdw[3] = D;
		MD5InBitsTotal = 0;
	}
	else
	{
		memcpy(HashCurrent, Hash, sizeof(HashCurrent));
	}
	MD5InBitsTotal += cbitsIn;

	// Step 4. Process Message in 16-Word Blocks
	for (cbCurrent = 0, cbRemain = cbitsIn / 8; cbRemain >= sizeof(M); cbCurrent += sizeof(M), cbRemain -= sizeof(M))
	{
		MD5Update(&in[cbCurrent], HashCurrent);
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
			MD5Update(M, HashCurrent);
			memset(M, 0, sizeof(M) - 8);
		}

		// Step 2. Append Length
		memcpy(&M[56], &MD5InBitsTotal, 8);

		MD5Update(M, HashCurrent);
	}

	// Step 5. Output
	memcpy(Hash, HashCurrent, sizeof(HashCurrent));

	return;
}

/* SHA */
DWORD WINAPI Ch32(DWORD x, DWORD y, DWORD z)
{
	DWORD Ret;

	Ret = (x & y) ^ ((~x) & z);

	return Ret;
}

DWORD64 WINAPI Ch64(DWORD64 x, DWORD64 y, DWORD64 z)
{
	DWORD64 Ret;

	Ret = (x & y) ^ ((~x) & z);

	return Ret;
}

DWORD WINAPI Parity32(DWORD x, DWORD y, DWORD z)
{
	DWORD Ret;

	Ret = x ^ y ^ z;

	return Ret;
}

DWORD WINAPI Maj32(DWORD x, DWORD y, DWORD z)
{
	DWORD Ret;

	Ret = (x & y) ^ (x & z) ^ (y & z);

	return Ret;
}

DWORD64 WINAPI Maj64(DWORD64 x, DWORD64 y, DWORD64 z)
{
	DWORD64 Ret;

	Ret = (x & y) ^ (x & z) ^ (y & z);

	return Ret;
}

DWORD BSIG032(DWORD x)
{
	DWORD Ret;

	Ret = ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22);

	return Ret;
}

DWORD64 BSIG064(DWORD64 x)
{
	DWORD64 Ret;

	Ret = ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39);

	return Ret;
}

DWORD WINAPI BSIG132(DWORD x)
{
	DWORD Ret;

	Ret = ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25);

	return Ret;
}

DWORD64 WINAPI BSIG164(DWORD64 x)
{
	DWORD64 Ret;

	Ret = ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41);

	return Ret;
}

DWORD WINAPI SSIG032(DWORD x)
{
	DWORD Ret;

	Ret = ROTR32(x, 7) ^ ROTR32(x, 18) ^ SHR32(x, 3);

	return Ret;
}

DWORD64 WINAPI SSIG064(DWORD64 x)
{
	DWORD64 Ret;

	Ret = ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR64(x, 7);

	return Ret;
}

DWORD WINAPI SSIG132(DWORD x)
{
	DWORD Ret;

	Ret = ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR32(x, 10);

	return Ret;
}

DWORD64 WINAPI SSIG164(DWORD64 x)
{
	DWORD64 Ret;

	Ret = ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR64(x, 6);

	return Ret;
}

BOOL WINAPI SHA1Update(BYTE M[64], DWORD Hash[5])
{
	DWORD t;
	DWORD W[80];
	DWORD a;
	DWORD b;
	DWORD c;
	DWORD d;
	DWORD e;
	DWORD T;
	DWORD(WINAPI * f)(DWORD x, DWORD y, DWORD z);

	for (t = 0; t < 16; t++)
	{
		W[t] = (
			(((DWORD)(M[t * 4]) << 24) & 0xFF000000) |
			(((DWORD)(M[t * 4 + 1]) << 16) & 0x00FF0000) |
			(((DWORD)(M[t * 4 + 2]) << 8) & 0x0000FF00) |
			(((DWORD)(M[t * 4 + 3])) & 0x000000FF)
			);
	}

	for (; t < 80; t++)
	{
		W[t] = ROTL32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
	}

	a = Hash[0];
	b = Hash[1];
	c = Hash[2];
	d = Hash[3];
	e = Hash[4];

	for (t = 0; t < 80; t++)
	{
		if (t <= 19)
		{
			f = Ch32;
		}
		else if (20 <= t && t <= 39)
		{
			f = Parity32;
		}
		else if (40 <= t && t <= 59)
		{
			f = Maj32;
		}
		else if (60 <= t && t <= 79)
		{
			f = Parity32;
		}

		T = ROTL32(a, 5) + f(b, c, d) + e + SHA1_K[t] + W[t];
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = T;
	}

	Hash[0] = a + Hash[0];
	Hash[1] = b + Hash[1];
	Hash[2] = c + Hash[2];
	Hash[3] = d + Hash[3];
	Hash[4] = e + Hash[4];

	return TRUE;
}

// SHA1 によるハッシュ作成
// in ... 入力データ
// cbitsIn ... 入力データのビット数
// bInit ... 最初の入力かどうか
// bFinish ... 最後の入力かどうか
// Hash ... 計算されたハッシュ
// ・入力されるメッセージの合計は 0～2^64 - 1ビット
// ・一度の入力で完了する場合、bInit と bFinish は両方 TRUE
// ・何度かに分割して入力する場合、最初と途中の入力は 512 ビット (64 バイト) の倍数である必要がある
// 　また最初の入力は bInit = TRUE, bFinish = FALSE 、途中の入力は bInit = FALSE, bFinish = FALSE、
// 　最後の入力は bInit = FALSE, bFinish = TRUE とする
VOID WINAPI SHA1(BYTE* in, DWORD64 cbitsIn, BOOL bInit, BOOL bFinish, DWORD* Hash) // DWORD Hash[5]
{
	BYTE M[64], * lpTotalBits;
	DWORD i, HashCurrent[5];
	DWORD64 cbitsRemain, cbRemain, cbCurrent, * lpdw64;

	if (bInit)
	{
		HashCurrent[0] = SHA1_INITIAL_HASH[0];
		HashCurrent[1] = SHA1_INITIAL_HASH[1];
		HashCurrent[2] = SHA1_INITIAL_HASH[2];
		HashCurrent[3] = SHA1_INITIAL_HASH[3];
		HashCurrent[4] = SHA1_INITIAL_HASH[4];
		SHA1InBitsTotal = 0;
	}
	else
	{
		memcpy(HashCurrent, Hash, sizeof(HashCurrent));
	}
	SHA1InBitsTotal += cbitsIn;

	for (cbCurrent = 0, cbRemain = cbitsIn / 8; cbRemain >= sizeof(M); cbCurrent += sizeof(M), cbRemain -= sizeof(M))
	{
		SHA1Update(&in[cbCurrent], HashCurrent);
	}

	if (bFinish)
	{
		lpdw64 = (DWORD64*)M;

		for (i = 0; i < 8; i++)
		{
			lpdw64[i] = 0;
		}

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
			SHA1Update(M, HashCurrent);
			memset(M, 0, sizeof(M) - 8);
		}

		lpTotalBits = (LPBYTE)&SHA1InBitsTotal;
		M[56] = lpTotalBits[7];
		M[57] = lpTotalBits[6];
		M[58] = lpTotalBits[5];
		M[59] = lpTotalBits[4];
		M[60] = lpTotalBits[3];
		M[61] = lpTotalBits[2];
		M[62] = lpTotalBits[1];
		M[63] = lpTotalBits[0];
		SHA1Update(M, HashCurrent);
	}

	memcpy(Hash, HashCurrent, sizeof(HashCurrent));

	return;
}

BOOL WINAPI SHA256Update(BYTE M[64], DWORD Hash[8])
{
	DWORD t;
	DWORD W[64];
	DWORD T1;
	DWORD T2;
	DWORD a;
	DWORD b;
	DWORD c;
	DWORD d;
	DWORD e;
	DWORD f;
	DWORD g;
	DWORD h;

	for (t = 0; t < 16; t++)
	{
		W[t] = (
			(((DWORD)(M[t * 4]) << 24) & 0xFF000000) |
			(((DWORD)(M[t * 4 + 1]) << 16) & 0x00FF0000) |
			(((DWORD)(M[t * 4 + 2]) << 8) & 0x0000FF00) |
			(((DWORD)(M[t * 4 + 3])) & 0x000000FF)
			);
	}

	for (; t < 64; t++)
	{
		W[t] = SSIG132(W[t - 2]) + W[t - 7] + SSIG032(W[t - 15]) + W[t - 16];

	}

	a = Hash[0];
	b = Hash[1];
	c = Hash[2];
	d = Hash[3];
	e = Hash[4];
	f = Hash[5];
	g = Hash[6];
	h = Hash[7];

	for (t = 0; t < 64; t++)
	{
		T1 = h + BSIG132(e) + Ch32(e, f, g) + SHA224_256_K[t] + W[t];
		T2 = BSIG032(a) + Maj32(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	Hash[0] = a + Hash[0];
	Hash[1] = b + Hash[1];
	Hash[2] = c + Hash[2];
	Hash[3] = d + Hash[3];
	Hash[4] = e + Hash[4];
	Hash[5] = f + Hash[5];
	Hash[6] = g + Hash[6];
	Hash[7] = h + Hash[7];

	return TRUE;
}

VOID WINAPI SHA256(BYTE* in, DWORD64 cbitsIn, BOOL bInit, BOOL bFinish, DWORD* Hash) // DWORD Hash[8]
{
	BYTE M[64], * lpTotalBits;
	DWORD i, HashCurrent[8];
	DWORD64 cbitsRemain, cbRemain, cbCurrent, * lpdw64;

	if (bInit)
	{
		HashCurrent[0] = SHA256_INITIAL_HASH[0];
		HashCurrent[1] = SHA256_INITIAL_HASH[1];
		HashCurrent[2] = SHA256_INITIAL_HASH[2];
		HashCurrent[3] = SHA256_INITIAL_HASH[3];
		HashCurrent[4] = SHA256_INITIAL_HASH[4];
		HashCurrent[5] = SHA256_INITIAL_HASH[5];
		HashCurrent[6] = SHA256_INITIAL_HASH[6];
		HashCurrent[7] = SHA256_INITIAL_HASH[7];
		SHA256InBitsTotal = 0;
	}
	else
	{
		memcpy(HashCurrent, Hash, sizeof(HashCurrent));
	}
	SHA256InBitsTotal += cbitsIn;

	for (cbCurrent = 0, cbRemain = cbitsIn / 8; cbRemain >= sizeof(M); cbCurrent += sizeof(M), cbRemain -= sizeof(M))
	{
		SHA256Update(&in[cbCurrent], HashCurrent);
	}

	if (bFinish)
	{
		lpdw64 = (DWORD64*)M;

		for (i = 0; i < 8; i++)
		{
			lpdw64[i] = 0;
		}

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
			SHA256Update(M, HashCurrent);
			memset(M, 0, sizeof(M) - 8);
		}

		lpTotalBits = (LPBYTE)&SHA256InBitsTotal;
		M[56] = lpTotalBits[7];
		M[57] = lpTotalBits[6];
		M[58] = lpTotalBits[5];
		M[59] = lpTotalBits[4];
		M[60] = lpTotalBits[3];
		M[61] = lpTotalBits[2];
		M[62] = lpTotalBits[1];
		M[63] = lpTotalBits[0];
		SHA256Update(M, HashCurrent);
	}

	memcpy(Hash, HashCurrent, sizeof(HashCurrent));

	return;
}

BOOL WINAPI SHA512Update(BYTE M[128], DWORD64 Hash[8])
{
	DWORD t;
	DWORD64 T1;
	DWORD64 T2;
	DWORD64 W[80];
	DWORD64 a;
	DWORD64 b;
	DWORD64 c;
	DWORD64 d;
	DWORD64 e;
	DWORD64 f;
	DWORD64 g;
	DWORD64 h;

	for (t = 0; t < 16; t++)
	{
		W[t] = (
			(((DWORD64)(M[8 * t]) << 56) & 0xFF00000000000000) |
			(((DWORD64)(M[8 * t + 1]) << 48) & 0x00FF000000000000) |
			(((DWORD64)(M[8 * t + 2]) << 40) & 0x0000FF0000000000) |
			(((DWORD64)(M[8 * t + 3]) << 32) & 0x000000FF00000000) |
			(((DWORD64)(M[8 * t + 4]) << 24) & 0x00000000FF000000) |
			(((DWORD64)(M[8 * t + 5]) << 16) & 0x0000000000FF0000) |
			(((DWORD64)(M[8 * t + 6]) << 8) & 0x000000000000FF00) |
			((DWORD64)(M[8 * t + 7]) & 0x00000000000000FF)
			);
	}

	while (t < 80)
	{
		W[t] = SSIG164(W[t - 2]) + W[t - 7] + SSIG064(W[t - 15]) + W[t - 16];
		t++;
	}

	a = Hash[0];
	b = Hash[1];
	c = Hash[2];
	d = Hash[3];
	e = Hash[4];
	f = Hash[5];
	g = Hash[6];
	h = Hash[7];

	for (t = 0; t < 80; t++)
	{
		T1 = h + BSIG164(e) + Ch64(e, f, g) + SHA384_512_K[t] + W[t];
		T2 = BSIG064(a) + Maj64(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	Hash[0] = a + Hash[0];
	Hash[1] = b + Hash[1];
	Hash[2] = c + Hash[2];
	Hash[3] = d + Hash[3];
	Hash[4] = e + Hash[4];
	Hash[5] = f + Hash[5];
	Hash[6] = g + Hash[6];
	Hash[7] = h + Hash[7];

	return TRUE;
}

VOID WINAPI SHA512(BYTE* in, DWORD64 cbitsIn, BOOL bInit, BOOL bFinish, DWORD64* Hash) // DWORD64 Hash[8]
{
	BYTE M[128], * lpTotalBits;
	DWORD i;
	DWORD64 cbitsRemain, cbRemain, cbCurrent, * lpdw64, HashCurrent[8];

	if (bInit)
	{
		HashCurrent[0] = SHA512_INITIAL_HASH[0];
		HashCurrent[1] = SHA512_INITIAL_HASH[1];
		HashCurrent[2] = SHA512_INITIAL_HASH[2];
		HashCurrent[3] = SHA512_INITIAL_HASH[3];
		HashCurrent[4] = SHA512_INITIAL_HASH[4];
		HashCurrent[5] = SHA512_INITIAL_HASH[5];
		HashCurrent[6] = SHA512_INITIAL_HASH[6];
		HashCurrent[7] = SHA512_INITIAL_HASH[7];
		SHA512InBitsTotal = 0;
	}
	else
	{
		memcpy(HashCurrent, Hash, sizeof(HashCurrent));
	}
	SHA512InBitsTotal += cbitsIn;

	for (cbCurrent = 0, cbRemain = cbitsIn / 8; cbRemain >= sizeof(M); cbCurrent += sizeof(M), cbRemain -= sizeof(M))
	{
		SHA512Update(&in[cbCurrent], HashCurrent);
	}

	if (bFinish)
	{
		lpdw64 = (DWORD64*)M;

		for (i = 0; i < 8; i++)
		{
			lpdw64[i] = 0;
		}

		cbitsRemain = cbitsIn % 1024;
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

		if (cbitsRemain >= 896)
		{
			SHA512Update(M, HashCurrent);
			memset(M, 0, sizeof(M) - 8);
		}

		lpTotalBits = (LPBYTE)&SHA512InBitsTotal;
		M[120] = lpTotalBits[7];
		M[121] = lpTotalBits[6];
		M[122] = lpTotalBits[5];
		M[123] = lpTotalBits[4];
		M[124] = lpTotalBits[3];
		M[125] = lpTotalBits[2];
		M[126] = lpTotalBits[1];
		M[127] = lpTotalBits[0];
		SHA512Update(M, HashCurrent);
	}

	memcpy(Hash, HashCurrent, sizeof(HashCurrent));

	return;
}

// n ビットを取り出し返す
// in ... 入力データ
// cbitsIn ... 入力データのビット数
// cbitsStart ... 開始ビット
// n ... 取り出すビット数。1～512まで
ULONG64 WINAPI GetNBits(BYTE* in, ULONG64 cbitsIn, ULONG64 cbitsStart, ULONG64 n)
{
	ULONG64 ret = 0, temp = 0, i, j, base, mod, nBits;
	BYTE mask;

	base = cbitsStart / 8;
	mod = cbitsStart % 8;

	mask = 0xff >> mod;
	ret = in[base] & mask;
	base++;

	if (cbitsIn < n)
	{
		nBits = cbitsIn;
	}
	else
	{
		nBits = n;
	}

	if ((nBits + mod) >= 8)
	{
		for (i = nBits - (8 - mod), j = base; i >= 8; i -= 8, j++)
		{
			ret <<= 8;
			ret += in[j];
		}

		if (i != 0)
		{
			ret <<= i;
			ret += in[j] >> (8 - i);
		}
	}
	else
	{
		ret >>= 8 - nBits - mod;
	}

	return ret;
}

// CRC 関数
// CRC4 ～ CRC64 までの CRC ハッシュを計算する
// in ... 入力データ
// cbitsIn ... 入力データのサイズ (ビット数)
// poly ... 生成多項式の先頭を除いた部分
// polyBits ... 生成多項式の次数
// IsRightToLeft ... 左シフトか否か (TRUE だと左シフト)
// IsXorOut ... 結果を xor するか否か
ULONG64 WINAPI CRC(BYTE* in, ULONG64 cbitsIn, ULONG64 crcInit, ULONG64 poly, ULONG64 polyBits, BOOL IsRightToLeft, BOOL IsXorOut)
{
	ULONG64 i, base, mod, length, dem, ret;

	// CRC の初期値
	ret = crcInit;

	// 答えの長さ(次数) = ループの回数
	length = cbitsIn - polyBits;

	// 除数の次数部分のビットを 1 にする
	dem = (ULONG64)1 << (polyBits - 1);

	// 入力データから n ビットを取り出す
	ret = GetNBits(in, cbitsIn, 0, polyBits);

	// CRC の計算
	for (i = 0; i < cbitsIn; i++)
	{
		// base ... 何バイト目か
		base = (i + polyBits) / 8;

		if (IsRightToLeft)
		{
			// 左シフト
			
			// mod ... 何ビット目か
			mod = 7 - (i + polyBits) % 8;

			if ((dem & ret) != 0)
			{
				ret ^= dem;

				ret <<= 1;

				if (base * 8 < cbitsIn)
				{
					ret |= (in[base] >> mod) & 1;
				}

				ret ^= poly;
			}
			else
			{
				ret <<= 1;

				if (base * 8 < cbitsIn)
				{
					ret |= (in[base] >> mod) & 1;
				}
			}
		}
		else
		{
			// 右シフト
			
			// mod ... 何ビット目か
			mod = (i + polyBits) % 8;

			if (ret & 1)
			{
				ret >>= 1;

				if (base * 8 < cbitsIn)
				{
					ret |= (in[base] << (7 - mod)) & dem;
				}

				ret ^= poly;
			}
			else
			{
				ret >>= 1;

				if (base * 8 < cbitsIn)
				{
					ret |= (in[base] << (7 - mod)) & dem;
				}
			}
		}
	}

	if (IsXorOut)
	{
		if (polyBits == 64)
		{
			return ~ret;
		}
		else
		{
			return (((ULONG64)1 << polyBits) - 1) & ~ret;
		}
	}
	else
	{
		return ret;
	}
}

INT main(INT argc, CHAR* argv[])
{
	// MD4
	// MD4 test suite :
	// MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
	// MD4("a") = bde52cb31de33e46245e05fbdbd6fb24
	// MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
	// MD4("message digest") = d9130a8164549fe818874806e1c7014b
	// MD4("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9
	// MD4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = 043f8582f241db351ce627e153e7f0e4
	// MD4("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = e33b4ddc9c38f2199c3e7b164fcc0536
	BYTE MD4_Hash[16];
	BYTE* MD4_Example1 = NULL;
	MD4(MD4_Example1, 0, TRUE, TRUE, MD4_Hash);

	BYTE MD4_Example2[] = { 'a' };
	MD4(MD4_Example2, 8, TRUE, TRUE, MD4_Hash);

	BYTE MD4_Example3[] = "abc";
	MD4(MD4_Example3, 24, TRUE, TRUE, MD4_Hash);

	BYTE MD4_Example4[] = "message digest";
	MD4(MD4_Example4, 14 * 8, TRUE, TRUE, MD4_Hash);

	BYTE MD4_Example5[] = "abcdefghijklmnopqrstuvwxyz";
	MD4(MD4_Example5, 26 * 8, TRUE, TRUE, MD4_Hash);

	BYTE MD4_Example6[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	MD4(MD4_Example6, 62 * 8, TRUE, TRUE, MD4_Hash);

	BYTE MD4_Example7[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
	MD4(MD4_Example7, 80 * 8, TRUE, TRUE, MD4_Hash);

	// MD5
	// MD5 test suite :
	// MD5("") = d41d8cd98f00b204e9800998ecf8427e
	// MD5("a") = 0cc175b9c0f1b6a831c399e269772661
	// MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
	// MD5("message digest") = f96b697d7cb7938d525a2f31aaf161d0
	// MD5("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
	// MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = d174ab98d277d9f5a5611c2c9f419d9f
	// MD5("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = 57edf4a22be3c955ac49da2e2107b67a

	BYTE MD5_Hash[16];
	BYTE* MD5_Example1 = NULL;
	MD5(MD5_Example1, 0, TRUE, TRUE, MD5_Hash);

	BYTE MD5_Example2[] = { 'a' };
	MD5(MD5_Example2, 8, TRUE, TRUE, MD5_Hash);

	BYTE MD5_Example3[] = "abc";
	MD5(MD5_Example3, 24, TRUE, TRUE, MD5_Hash);

	BYTE MD5_Example4[] = "message digest";
	MD5(MD5_Example4, 14 * 8, TRUE, TRUE, MD5_Hash);

	BYTE MD5_Example5[] = "abcdefghijklmnopqrstuvwxyz";
	MD5(MD5_Example5, 26 * 8, TRUE, TRUE, MD5_Hash);

	BYTE MD5_Example6[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	MD5(MD5_Example6, 62 * 8, TRUE, TRUE, MD5_Hash);

	BYTE MD5_Example7[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
	MD5(MD5_Example7, 80 * 8, TRUE, TRUE, MD5_Hash);

	BYTE MD5_Example7_Part1[] = "1234567890123456789012345678901234567890123456789012345678901234";
	BYTE MD5_Example7_Part2[] = "5678901234567890";
	MD5(MD5_Example7_Part1, 64 * 8, TRUE, FALSE, MD5_Hash);
	MD5(MD5_Example7_Part2, 16 * 8, FALSE, TRUE, MD5_Hash);

	// SHA1
	// SHA1 test suite :
	// SHA1("abc") = A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
	// SHA1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1

	BYTE SHA_Example1[] = "abc";
	BYTE SHA_Example2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	BYTE SHA_Example3[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

	DWORD SHA1_Hash[5];
	SHA1(SHA_Example1, 3 * 8, TRUE, TRUE, SHA1_Hash);
	SHA1(SHA_Example2, 56 * 8, TRUE, TRUE, SHA1_Hash);

	// SHA256
	// SHA256 test suite :
	// SHA256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
	// SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1

	DWORD SHA256_Hash[8];
	SHA256(SHA_Example1, 3 * 8, TRUE, TRUE, SHA256_Hash);
	SHA256(SHA_Example2, 56 * 8, TRUE, TRUE, SHA256_Hash);

	// SHA512
	// SHA512 test suite :
	// SHA512("abc") = ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f
	// SHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be90

	DWORD64 SHA512_Hash[8];
	SHA512(SHA_Example1, 3 * 8, TRUE, TRUE, SHA512_Hash);
	SHA512(SHA_Example3, 112 * 8, TRUE, TRUE, SHA512_Hash);

	// CRC
	// CRC test
	// Data ... ad
	// polynomial ... 0x8408
	// poly bits ... 16
	// init (seed) ... 0
	// bit shift ... left to right
	// xor out ... no
	// ret ... 7eef
	BYTE CRC_Example[1] = { 0xad };
	DWORD64 CRC_InBits = 8;
	DWORD64 CRC16_Poly = 0x8408;
	DWORD64 CRC16_PolyBits = 16;
	DWORD64 CRC16_Init = 0;
	DWORD64 CRC16_Ret;
	CRC16_Ret = CRC(CRC_Example, CRC_InBits, CRC16_Init, CRC16_Poly, CRC16_PolyBits, FALSE, FALSE);

	return 0;
}