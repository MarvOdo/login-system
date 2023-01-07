#pragma once
#include <iostream>
#include <bitset>
#include <cmath>
#include <string>
#include <iomanip>

using namespace std;

class Encryption
{
public:
	string SHA256(string message)
	{
		//constants
		unsigned long h0 = 0x6a09e667;
		unsigned long h1 = 0xbb67ae85;
		unsigned long h2 = 0x3c6ef372;
		unsigned long h3 = 0xa54ff53a;
		unsigned long h4 = 0x510e527f;
		unsigned long h5 = 0x9b05688c;
		unsigned long h6 = 0x1f83d9ab;
		unsigned long h7 = 0x5be0cd19;

		//more constants
		unsigned long k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
					0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
					0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
					0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
					0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
					0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
					0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
					0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

		//pre-processing / padding
		int original_L = message.length() * 8; //(length is # of characters * 8 bits / char)
		string binaryMessage;
		for (int i = 0; i < message.length(); i++)
		{
			binaryMessage.append(bitset<8>(message[i]).to_string()); //append each character in binary
		}
		binaryMessage.append("1"); //append 1
		int K = 512 - ((original_L + 1 + 64) % 512);
		for (int i = 0; i < K; i++)
		{
			binaryMessage.append("0"); //append necessary number of padding 0s
		}
		binaryMessage.append(bitset<64>(original_L).to_string()); //append length in binary
		int padded_L = binaryMessage.length();

		//looking at message in 512-bit chunks
		for (int cnum = 0; cnum < padded_L / 512; cnum++)
		{
			string chunk = binaryMessage.substr(512 * cnum, 512);

			unsigned long w[64];
			for (int i = 0; i < 16; i++)
			{
				string tempWord = chunk.substr(32 * i, 32);
				char word[33];
				strcpy_s(word, tempWord.c_str());
				w[i] = strtoul(word, NULL, 2); //copy 32-bit from chunk into w array
			}

			//fill up rest of w array
			//	note: bitwise right rotation by n bits is equivalent to
			//	(right shift n) OR (left shift (32 - n))
			//	since we use unsigned long ints (32 bits long)
			for (int i = 16; i < 64; i++)
			{
				unsigned long s0 = ((w[i - 15] >> 7) | (w[i - 15] << (32 - 7))) ^
					((w[i - 15] >> 18) | (w[i - 15] << (32 - 18))) ^
					(w[i - 15] >> 3);
				unsigned long s1 = ((w[i - 2] >> 17) | (w[i - 2] << (32 - 17))) ^
					((w[i - 2] >> 19) | (w[i - 2] << (32 - 19))) ^
					(w[i - 2] >> 10);
				w[i] = w[i - 16] + s0 + w[i - 7] + s1;
			}

			//working variables
			unsigned long a = h0;
			unsigned long b = h1;
			unsigned long c = h2;
			unsigned long d = h3;
			unsigned long e = h4;
			unsigned long f = h5;
			unsigned long g = h6;
			unsigned long h = h7;

			//main loop
			for (int i = 0; i < 64; i++)
			{
				unsigned long S1 = ((e >> 6) | (e << (32 - 6))) ^
					((e >> 11) | (e << (32 - 11))) ^
					((e >> 25) | (e << (32 - 25)));
				unsigned long ch = (e & f) ^ ((~e) & g);
				unsigned long temp1 = h + S1 + ch + k[i] + w[i];
				unsigned long S0 = ((a >> 2) | (a << (32 - 2))) ^
					((a >> 13) | (a << (32 - 13))) ^
					((a >> 22) | (a << (32 - 22)));
				unsigned long maj = (a & b) ^ (a & c) ^ (b & c);
				unsigned long temp2 = S0 + maj;

				h = g;
				g = f;
				f = e;
				e = d + temp1;
				d = c;
				c = b;
				b = a;
				a = temp1 + temp2;
			}

			h0 = h0 + a;
			h1 = h1 + b;
			h2 = h2 + c;
			h3 = h3 + d;
			h4 = h4 + e;
			h5 = h5 + f;
			h6 = h6 + g;
			h7 = h7 + h;
		}

		string digest;
		char hex[8][9];
		//save unsigned longs h0 - h7 as char[] in hexadecimal
		sprintf_s(hex[0], "%X", h0);
		sprintf_s(hex[1], "%X", h1);
		sprintf_s(hex[2], "%X", h2);
		sprintf_s(hex[3], "%X", h3);
		sprintf_s(hex[4], "%X", h4);
		sprintf_s(hex[5], "%X", h5);
		sprintf_s(hex[6], "%X", h6);
		sprintf_s(hex[7], "%X", h7);
		for (int i = 0; i < 8; i++)
		{
			digest.append(hex[i]);
		}

		return digest;
	}
};