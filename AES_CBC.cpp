/**************************************************************************
************************** AES128 in CBC***********************************
**************************************************************************/ 


#include <iostream>
using namespace std;


//Next two rows is the realization of multiplying in GF
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))


int Nr = 10;				//Num of Rounds
unsigned char Round_Key[16]; 		//Round key itself
unsigned char KeyShedule[11][16];	//Table that keeps round keys
unsigned char Cipher_Key[16];		//Cipher key itself
unsigned char State[16];		//Temporary result
const unsigned char Sbox[256] = 	
{
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
const unsigned char InvSbox[256] = 
{
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
//There is no need to write down all Rcon, because only 10 elements are used
const unsigned char Rcon[10] = 
{
        	0x01, 0x02,0x04,0x08,0x10,0x20, 0x40, 0x80, 0x1b, 0x36
};

//Write inpute through columns, not rows
void CopyTo(unsigned char out[], unsigned char in[])
{
	for(int j=0; j<4 ; j++ )
        {
       		for(int i=0; i<4; i++)
       		{
       			out[i*4+j] = in[i+4*j];
       		}
       	}
}
//Replace elements       
void swap(unsigned char &a,unsigned char &b)
{
     	unsigned char t=a;
     	a=b;
     	b=t;
}
//Simple XOR
void AddRoundKey(unsigned char State[], unsigned char Round_Key[])
{
	for(int j=0; j<4 ; j++ )
       	{
       		for(int i=0; i<4; i++)
       		{
       			State[i*4+j] ^= Round_Key[i*4+j];
       		}
       	}
}
//Substitution 
void SubBytes(unsigned char State[])
{
	unsigned char I;
        unsigned char J;
	for (int i=0; i<4; i++)
        {
        	for(int j=0; j<4;j++)
        	{
        		I = State[i*4+j]>>4;
        		J = State[i*4+j]<<4;
        		J=J>>4;
        		State[i*4+j] = Sbox[I*16+J];
        	}
        }
}
//Inverse Substitution
void InvSubBytes(unsigned char State[])
{
	for (int i=0; i<4; i++)
        {
        	for(int j=0; j<4;j++)
        	{
        		unsigned char I = State[i*4+j]>>4;
        		unsigned char J = State[i*4+j]<<4;
        		J=J>>4;
        		State[i*4+j] = InvSbox[I*16+J];
        	}
        }
}
//Cycle shift rows
void ShiftRows(unsigned char State[])
{
	//first line stays the same
     	char temp;
     	//second line
     	temp=State[4];
     	for( int i = 4; i<8 ; i++)
     		State[i]=State[i+1];
     	State[7] =temp;
     	//third line
     	
     	swap(State[8], State[10]);
     	swap(State[9], State[11]);
     	//fourth line
     	swap(State[12], State[13]);
     	swap(State[12], State[14]);
     	swap(State[12], State[15]);

}
//Inverse shift rows
void InvShiftRows(unsigned char State[])
{
	char temp;
     	//second line
     	temp=State[7];
     	for( int i = 7; i>4 ; i--)
     		State[i]=State[i-1];
     	State[4] =temp;
     	//third line
     	swap(State[8], State[10]);
     	swap(State[9], State[11]);
     	//fourth line
     	swap(State[12], State[13]);
     	swap(State[13], State[14]);
     	swap(State[14], State[15]);

     
}
//Filling the KeyShedule with Round Keys
void KeyExpansion(unsigned char KeyShedule[11][16], unsigned char Cipher_Key[])
{
	for(int i=0; i<16;i++)
       		KeyShedule[0][i]=Cipher_Key[i]; 	//Round Key for INIT Round is the Cipher Key
	//Calculating Round Keys
	for (int count = 1; count <= 11; count++)
	{
		//First Column
		KeyShedule[count][0]=KeyShedule[count-1][7];
		KeyShedule[count][4]=KeyShedule[count-1][11];
		KeyShedule[count][8]=KeyShedule[count-1][15];
		KeyShedule[count][12]=KeyShedule[count-1][3];
		for(int i=0; i<4; i++)
		{
			unsigned char I = KeyShedule[count][4*i]>>4;
			unsigned char J = KeyShedule[count][4*i]<<4;
			J=J>>4;
			KeyShedule[count][4*i] = Sbox[I*16+J];
		}
		
	       	KeyShedule[count][0]^=KeyShedule[count-1][0]^Rcon[count-1];
	       	KeyShedule[count][4]^=KeyShedule[count-1][4];
	       	KeyShedule[count][8]^=KeyShedule[count-1][8];
	       	KeyShedule[count][12]^=KeyShedule[count-1][12];
	       	//Second Column
	       	KeyShedule[count][1]^=KeyShedule[count-1][1]^KeyShedule[count][0];
	       	KeyShedule[count][5]^=KeyShedule[count-1][5]^KeyShedule[count][4];
	       	KeyShedule[count][9]^=KeyShedule[count-1][9]^KeyShedule[count][8];
	       	KeyShedule[count][13]^=KeyShedule[count-1][13]^KeyShedule[count][12];
	       	//Third Column
	       	KeyShedule[count][2]^=KeyShedule[count-1][2]^KeyShedule[count][1];
	       	KeyShedule[count][6]^=KeyShedule[count-1][6]^KeyShedule[count][5];
	       	KeyShedule[count][10]^=KeyShedule[count-1][10]^KeyShedule[count][9];
	       	KeyShedule[count][14]^=KeyShedule[count-1][14]^KeyShedule[count][13];
	       	//Fourth Column
	       	KeyShedule[count][3]^=KeyShedule[count-1][3]^KeyShedule[count][2];
	       	KeyShedule[count][7]^=KeyShedule[count-1][7]^KeyShedule[count][6];
	       	KeyShedule[count][11]^=KeyShedule[count-1][11]^KeyShedule[count][10];
	       	KeyShedule[count][15]^=KeyShedule[count-1][15]^KeyShedule[count][14];
	       	
	}
}
// MixColumns function mixes the columns of the state matrix
void MixColumns(unsigned char State[])
{
	int i;
	unsigned char a,b,c,d;
	for(i=0;i<4;i++)

	{
		a = State[i];
		b = State[4+i];
		c = State[8+i];
		d = State[12+i];

		State[i] = Multiply(a, 0x2) ^ Multiply(b, 0x3) ^ c ^ d;
		State[4+i] = a ^ Multiply(b, 0x2) ^ Multiply(c, 0x3) ^ d;
		State[8+i] = a ^ b ^ Multiply(c, 0x2) ^ Multiply(d, 0x3);
		State[12+i] = Multiply(a, 0x3) ^ b ^ c ^ Multiply(d, 0x2);
	}

}
//Inverse MixColumns
void InvMixColumns(unsigned char State[])
{
	int i;
	unsigned char a,b,c,d;
	for(i=0;i<4;i++)
	{	
	
		a = State[i];
		b = State[4+i];
		c = State[8+i];
		d = State[12+i];

		
		State[i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		State[4+i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		State[8+i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		State[12+i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}
//Checking State     	
void CheckState(unsigned char State[16])
{
	for (int i=0; i<4; i++)
       	{
       		for(int j=0; j<4;j++)
       			cout << hex <<int(State[4*i+j])<<' ';
       		cout <<endl;
      	}
      	cout << endl;
}
void BLOCK_ENCRYPT(unsigned char State[], unsigned char Cipher_Key[])
{
	//INIT ROUND 
	int curRound=0;
	 
	for(int i=0; i<16;i++)
       		Round_Key[i]=Cipher_Key[i];
       	curRound++;
	AddRoundKey(State, KeyShedule[0]);
	//ROUNDS 1-9
       	
       	while(curRound<=9)
       	{
	       	SubBytes(State);
	       	ShiftRows(State);
	       	MixColumns(State);
	       	AddRoundKey(State, KeyShedule[curRound]);
	       	curRound++;
	       	
	}

	//ROUND 10
	
	SubBytes(State);
	ShiftRows(State);
	AddRoundKey(State, KeyShedule[10]);
}


void BLOCK_DECRYPT(unsigned char State[], unsigned char Cipher_Key[])
{
	//INIT ROUND
	for(int i=0; i<16;i++)
       		Round_Key[i]=Cipher_Key[i];
	AddRoundKey(State, KeyShedule[10]);
	InvShiftRows(State);
      	InvSubBytes(State);
        AddRoundKey(State, KeyShedule[9]);
	//ROUND 1-9
	int curRound=1;
       	
       	
       	while(curRound<=9)
       	{
       		InvMixColumns(State);
	       	InvShiftRows(State);
	       	InvSubBytes(State);
	        AddRoundKey(State, KeyShedule[9-curRound]);
       		curRound++;
	}


}



int main(int argc, char *argv[])
{
		
        char choise = 0;
        unsigned char InputBlock[16];
        unsigned char InputKey[16]={};
        cout <<"(M)anual key \n(G)enerate key \n(E)xtract the key from file password.txt\n";
        cin >> choise;
        if(choise=='G')
        {
        	FILE * key = fopen("password.txt","w");
		if (key == NULL) 
		{
		    perror ("Error opening password.txt");
		    return -1;
		}
		FILE *VI = fopen("/dev/urandom", "r");
		if (VI == NULL) 
		{
		    perror("Error opening VI");
		    return -1;
        	}
        	fread(InputKey, 1, 16, VI);
		fwrite(InputKey,1,16,key);
		fclose(key);
		fclose(VI);
    	}
	else if (choise=='M')
	{
		cout <<"Enter the key\n";
		cin >> InputKey;
	}
	else if (choise=='E')
	{
		FILE * key = fopen("password.txt","r");
		if (key == NULL) 
		{
		    perror ("Error opening password.txt");
		    return -1;
		}
		fread(InputKey,1,16,key);
		fclose(key);
	}
	else 
	{
		perror("WATCH YOUR INPUT!!!");
		return -1;
	}
	    
		//Copy Input to State
	CopyTo(State, InputBlock);
    	CopyTo(Cipher_Key, InputKey);
    	cout<< "Key:" << endl;
    	CheckState(Cipher_Key);
    	cout << endl;
       	
    	KeyExpansion(KeyShedule, Cipher_Key);
    	cout << "What to do? (e/d)" << endl;
    	char choise2=0;
    	cin >> choise2;
    	if (choise2=='e')
    	{
    		FILE *plaintext = fopen(argv[1], "r+");
	    	if (plaintext != NULL)
	    	{
		FILE *VI = fopen("/dev/urandom", "r");
		if (VI == NULL) 
			perror("Error opening VI");
		FILE *cyphertext = fopen("cyphertext.txt", "w");
		if (cyphertext == NULL) 
			perror("Error opening cyphertext");
		
		unsigned char roundtext[16];
		unsigned char oldtext[16];
		unsigned short i, j;
		char a = 0;
		fseek(plaintext, 0, 2);
		unsigned int filesize = ftell(plaintext);
		
		fread(oldtext, 1, 16, VI);
		fwrite(oldtext, 1, 16, cyphertext);
		if(filesize % 16 >0 )
			for (i = 0; i < 16 - filesize % 16; i++) 
				fwrite(&a, 1, 1, plaintext);
		filesize = ftell(plaintext);
		
		fseek(plaintext, 0, 0);
		for (j = 0; j < filesize / 16; j++) 
		{
		    fread(roundtext, 1, 16, plaintext);
		    for (i = 0; i < 16; i++) 
		    	roundtext[i] ^= oldtext[i];
		    BLOCK_ENCRYPT(roundtext, Cipher_Key);
		    fwrite(roundtext, 1, 16, cyphertext);
		    for (i = 0; i < 16; i++) 
		    	oldtext[i] = roundtext[i];
		}
		
		fclose(VI);
		fclose(cyphertext);
		fclose(plaintext);
		cout << "OOPS, YOUR FILE HAS BEEN ENCRYPTED\ncheck cyphertext.txt to see result\n";
        }
    	else perror("Error opening plaintext");
    
    	}
	else if ( choise2 =='d')
	{
		if(choise =='G')
    			cout << "Interesting. Probability of generanting the right key is 1/2^128...Good Luck!!\n";
	    	FILE * plaintext = fopen("plaintext.txt", "w");
       	        if (plaintext == NULL) 
	    		perror ("Error opening plaintext");
	        FILE * cyphertext = fopen(argv[1], "r");
	        if (cyphertext != NULL)
	        {
			fseek(cyphertext,0,2);
			unsigned int filesize = ftell(cyphertext);
			unsigned char roundtext[16];
			unsigned char oldtext[16];
			unsigned short i, j;
			fseek(cyphertext,0,2);
		
			for (j = 0; j < ((filesize-16) / 16); j++) 
			{
			    fseek(cyphertext, -16, 1);
			    fread(roundtext, 1, 16, cyphertext);
			    BLOCK_DECRYPT(roundtext, Cipher_Key);
			    fseek(cyphertext, -32, 1);
			    fread(oldtext, 1, 16, cyphertext);
			    for (i = 0; i < 16; i++) 
			    	roundtext[i] ^= oldtext[i];
			    fseek(plaintext,16*((filesize/16)-j-2),0);
			    fwrite(roundtext,1,16,plaintext);
		}
		fclose(cyphertext);
		cout << "OOPS, YOUR FILE HAS BEEN DECRYPTED\n";
		}
	        else perror ("Error opening cyphertext");
	        fclose(plaintext);
	}
	else perror ("WATCH YOUR INPUT");
    	return 0;
     
}
    
