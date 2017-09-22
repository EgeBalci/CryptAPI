#include "headers.h"
SIZE_T stupid_strlen(CONST CHAR* str)
{
	size_t len = 0;
	for (char* buf = (char*)str; *buf != 0; buf++, len++);
	return len;
}
// can also do
/*
INT stupid_strlen(CHAR* s) {
INT c = 0;

while (*s++ != 0)
c++;

return c;
}
lol
dont judge k thx
*/
void *_memcpy(void* dest, const void* src, size_t count) {
	char* dst8 = (char*)dest;
	char* src8 = (char*)src;

	while (count--) {
		*dst8++ = *src8++;
	}
	return dest;
}
