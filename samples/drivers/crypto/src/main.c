/*
> openssl enc -nosalt -aes-256-cbc -k hello-aes -P                                                                  
*** WARNING : deprecated key derivation used.                                                                                                                 
Using -iter or -pbkdf2 would be better.                                                                                                                       
key=E8B6C00C9ADC5E75BB656ECD429CB1643A25B111FCD22C6622D53E0722439993                                                                                          
iv =E486BB61EB213ED88CC3CFB938CD58D7
*/

#include <stdio.h>
#include <device.h>
#include <zephyr.h>
#include <string.h>
#include <crypto/cipher.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main);

#include <mbedtls/gcm.h>

void main(void)
{
	mbedtls_gcm_context aes;
	/*
	   unsigned char key[] = {
	   0x45, 0x38, 0x42, 0x36, 0x43, 0x30, 0x30, 0x43, 0x39, 0x41, 0x44, 0x43,
	   0x35, 0x45, 0x37, 0x35, 0x42, 0x42, 0x36, 0x35, 0x36, 0x45, 0x43, 0x44,
	   0x34, 0x32, 0x39, 0x43, 0x42, 0x31, 0x36, 0x34, 0x33, 0x41, 0x32, 0x35,
	   0x42, 0x31, 0x31, 0x31, 0x46, 0x43, 0x44, 0x32, 0x32, 0x43, 0x36, 0x36,
	   0x32, 0x32, 0x44, 0x35, 0x33, 0x45, 0x30, 0x37, 0x32, 0x32, 0x34, 0x33,
	   0x39, 0x39, 0x39, 0x33
	   };
	 */
	unsigned char *key = "abcdefghijklmnopabababababababab";
#if 0
	unsigned char key[] = {
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
		0x6d, 0x6e, 0x6f, 0x70, 0x61, 0x62, 0x61, 0x62, 0x61, 0x62, 0x61, 0x62,
		0x61, 0x62, 0x61, 0x62, 0x61, 0x62, 0x61, 0x62
	};
#endif
	char *input = "Mark C's ESP32 GCM Example code!a";
	unsigned char *iv = "abababababababab";
#if 0
	unsigned char iv[] = {
		0x61, 0x62, 0x61, 0x62, 0x61, 0x62, 0x61, 0x62, 0x61, 0x62, 0x61, 0x62,
		0x61, 0x62, 0x61, 0x62
	};
#endif

	/*
	   unsigned char iv[] = {
	   0x45, 0x34, 0x38, 0x36, 0x42, 0x42, 0x36, 0x31, 0x45, 0x42, 0x32, 0x31,
	   0x33, 0x45, 0x44, 0x38, 0x38, 0x43, 0x43, 0x33, 0x43, 0x46, 0x42, 0x39,
	   0x33, 0x38, 0x43, 0x44, 0x35, 0x38, 0x44, 0x37
	   };
	 */

	unsigned char output[64] = {0};
	unsigned char fin[64] = {0};
	size_t out_len;
	int rc = -1;

	printf("%s\n", key);
	// init the context...
	mbedtls_gcm_init( &aes );
	// Set the key. This next line could have CAMELLIA or ARIA as our GCM mode cipher...
	mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , key, strlen(key) * 8);
	// Initialise the GCM cipher...
	rc = mbedtls_gcm_starts(&aes, MBEDTLS_GCM_ENCRYPT, iv, strlen(iv));
	//rc = mbedtls_gcm_starts(&aes, MBEDTLS_GCM_ENCRYPT, "abababababababab", strlen("abababababababab"));
	printf("rc %d\n", rc);
	// Send the intialised cipher some data and store it...
	mbedtls_gcm_update(&aes,(const unsigned char*)input, strlen(input), output, sizeof(output), &out_len);
	printf("out %d\n", out_len);
	// Free up the context.
	mbedtls_gcm_free( &aes );

#if 1
	for (int i = 0; i < strlen(input); i++) {  
		printf("I 0x%x -- 0x%x\n", (int)input[i], (int)output[i]);
	}
#endif

#if 1
	mbedtls_gcm_init( &aes );
	mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , key, strlen(key) * 8);
	mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, iv, strlen(iv));
	//	mbedtls_gcm_update(&aes,(const unsigned char*)output, strlen(output), fin, sizeof(fin), &out_len);
	//	printf("out %d\n", out_len);

	mbedtls_gcm_update(&aes,(const unsigned char*)output, 16, fin, sizeof(fin), &out_len);
	printf("out %d\n", out_len);
	mbedtls_gcm_update(&aes,(const unsigned char*)&output[16], 16, &fin[16], sizeof(fin), &out_len);
	printf("out %d\n", out_len);
	mbedtls_gcm_update(&aes,(const unsigned char*)&output[32], 1, &fin[32], sizeof(fin), &out_len);
	printf("out %d\n", out_len);
	char tag[16] = {0};
	//rc = mbedtls_gcm_finish(&aes, &fin[32], sizeof(fin), &out_len, tag, 16);
	rc = mbedtls_gcm_finish(&aes, NULL, 0, NULL, tag, 16);
	printf("%d \n", rc); //, out_len);

	mbedtls_gcm_free( &aes );

	for (int i = 0; i < strlen(input); i++) {  
		if (input[i] == fin[i])
			printf("S %c -- %c 0x%x -- 0x%x\n", (int)input[i], (int)fin[i], (int)input[i], (int)fin[i]);
		else
			printf("D 0x%x -- 0x%x\n", (int)input[i], (int)fin[i]);
	}
#endif
}
