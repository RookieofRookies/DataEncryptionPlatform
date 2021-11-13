
#ifndef _KEYMNG_Crypt_H_
#define _KEYMNG_Crypt_H_

#include "keymng_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

int MngCrypt_View(int shmhdl, int maxnode);

int MngCrypt_Encrypt(int shmkey, int maxnode);

int MngCrypt_Decrypt(int shmkey, int maxnode);


#ifdef __cplusplus
}
#endif

#endif

