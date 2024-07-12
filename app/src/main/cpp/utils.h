#ifndef ELFENCRYTEST_UTILS_H
#define ELFENCRYTEST_UTILS_H

#include <stddef.h>

void my_clear_cache(void *s, void *e);
void decrypt(unsigned char* data, size_t size, const unsigned char* key, const unsigned char* iv);
// char* bytesToHex(const unsigned char* bytes, int length);

#endif //ELFENCRYTEST_UTILS_H
