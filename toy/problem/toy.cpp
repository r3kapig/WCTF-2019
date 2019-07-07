#include <iostream>
#include <fstream>
#include <string>
#include <nmmintrin.h>
using namespace std;
__m128i reg;
__m128i mask;
char wf[131073];

bool checkflag(string flag)
{
	if (flag.length() != 38 || flag[0] != 'f' || flag[1] != 'l' || flag[2] != 'a' || flag[3] != 'g' || flag[4] != '{' || flag[37] != '}')
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool exact_initialreg_from_flag(string flag, unsigned char* mem_initial_reg)
{
	int i, point = 15;
	uint16_t tmp, left, right;
	for (i = 5; i < 37; i += 2)
	{
		if (flag[i] >= 'a' && flag[i] <= 'f')
		{
			left = flag[i] - 'a' + 0xa;
		}
		else if (flag[i] >= '0' && flag[i] <= '9')
		{
			left = flag[i] - '0';
		}
		else
		{
			return false;
		}

		if (flag[i + 1] >= 'a' && flag[i + 1] <= 'f')
		{
			right = flag[i + 1] - 'a' + 0xa;
		}
		else if (flag[i + 1] >= '0' && flag[i + 1] <= '9')
		{
			right = flag[i + 1] - '0';
		}
		else
		{
			return false;
		}
		tmp = 0;
		tmp = (left << 4) ^ right;
		*(mem_initial_reg + point) = tmp;
		point--;
	}
	return true;
}

void show128(const char info[], __m128i r)
{
	printf("%s:", info);
	uint8_t tmp[16];
	_mm_storeu_si128((__m128i*)tmp, r);
	int i;
	for (i = 15; i >= 0; i--)
	{
		printf("%02x", tmp[i]);
	}
	printf("\n");
}

uint8_t xor128()
{
	int i, j;
	uint8_t lastbit,mem[16];
	uint8_t tmp;
	__m128i temp_result=_mm_and_si128(reg, mask);
	_mm_storeu_si128((__m128i*)mem, temp_result);
	lastbit = 0;
	for (i = 15; i >=0 ; i--)
	{
		tmp = mem[i];
		for (j = 0; j < 8; j++)
		{
			lastbit = lastbit ^ (tmp & 0x1);
			tmp = tmp >> 1;
		}
	}
	return lastbit;
}

void lshift_xorlastbit(uint8_t lastbit)
{

	reg= _mm_xor_si128(_mm_slli_epi64(reg, 1), _mm_unpacklo_epi64(_mm_srli_si128(_mm_srli_epi64(reg, 63), 8), _mm_srli_epi64(reg, 63)));
	
	uint8_t set0[16], setlastbit[16];
	int i;
	for (i = 1; i < 16; i++)
	{
		set0[i] = 0xff;
		setlastbit[i] = 0;
	}
	set0[0] = 0xfe;
	setlastbit[0] = lastbit;
	__m128i set0m128 = _mm_lddqu_si128((__m128i*)set0);
	__m128i setlastbitm128 = _mm_lddqu_si128((__m128i*)setlastbit);
	reg = _mm_and_si128(reg,set0m128);
	reg = _mm_xor_si128(reg, setlastbitm128);
}

void lfsr()
{
	uint8_t lastbit=xor128();
	lshift_xorlastbit(lastbit);
}

uint8_t feed()
{
	uint8_t a[63] = { 78, 65, 90, 99, 117, 113, 87, 119, 64, 69, 114, 86, 72, 123, 91, 103, 124, 93, 79, 82, 76, 84, 106, 73, 110, 92, 118, 63, 109, 101, 67, 122, 98, 111, 80, 105, 108, 107, 100, 81, 125, 71, 96, 83, 75, 68, 95, 74, 104, 112, 121, 115, 77, 89, 85, 97, 70, 120, 88, 66, 94, 102, 116 };
	uint8_t origin[16],tmp,outbit;
	uint8_t x[128];
	int i,j,k;
	memset(x, 0, sizeof(x));
	_mm_storeu_si128((__m128i*)origin, reg);
	k = 0;
	for (i = 0; i < 16; i++)
	{
		tmp = origin[i];
		for (j = 0; j < 8; j++)
		{
			x[k] = tmp & 0x1;
			tmp = tmp >> 1;
			k += 1;
		}
	}

	outbit = x[127];
	for (i = 0; i < 63; i++)
	{
		outbit ^= (x[i] ^ x[a[i]] & 0x1);
	}
	outbit ^= x[11] & x[22] & x[33] & x[53] & 1;
	outbit ^= x[1] & x[9] & x[12] & x[18] & x[20] & x[23] & x[25] & x[26] & x[28] & x[33] & x[38] & x[41] & x[42] & x[51] & x[53] & x[59];
	tmp = 1;
	for (i = 0; i < 63; i++)
	{
		tmp &= x[i];
	}
	outbit ^= (tmp & 0x1);
	return outbit & 0x1;
}

int main()
{
	int i, j;
	uint8_t tmp;
	string flag;
	uint8_t initialreg[16];
	uint8_t initialmask[16] = { 0xba,0x4d,0x6d,0xd4,0x30,0xfa,0x71,0xd8,0x1b,0x33,0xe7,0xa8,0x3f,0x4d,0x4e,0xb6 };
	ifstream secret("flag.txt");
	secret >> flag;
	if (!checkflag(flag) || !exact_initialreg_from_flag(flag, initialreg))
	{
		cout << "> Invalid flag.txt" << endl;
		return 0;
	}
	reg = _mm_lddqu_si128((__m128i*)initialreg);
	mask = _mm_lddqu_si128((__m128i*)initialmask);
	cout << "> Loading is done" << endl;

	wf[131072] = 0;
	for (i = 0; i < 2048; i++)
	{

		if (i % 128 == 0)
		{
			cout << "> Processing......" << i / 128 << "/" << 16<<endl;
		}
		tmp = 0;
		for (j = 0; j < 8; j++)
		{
			lfsr();
			tmp = (tmp << 1) ^ feed();
		}
		wf[i] = tmp;
	}

	ofstream fout;
	fout.open("output", ofstream::binary);
	fout.write(wf, 2048);
	fout.close();

	cout << "> Down" << endl;

	return 0;
}
