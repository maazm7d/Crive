#include <stdio.h>
#include <stdint.h>
int main() {
    FILE *f = fopen("test_rar3.rar", "wb");
    fwrite("Rar!\x1a\x07\x00", 1, 7, f);
    uint8_t mhdr[] = {0,0,0x73,0x80,0,0x07,0};
    fwrite(mhdr, 1, 7, f);
    uint8_t salt[8] = {1,2,3,4,5,6,7,8};
    fwrite(salt, 1, 8, f);
    uint8_t enc[16] = {0};
    fwrite(enc, 1, 16, f);
    fclose(f);
    return 0;
}
