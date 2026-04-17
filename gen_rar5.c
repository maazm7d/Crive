#include <stdio.h>
#include <stdint.h>
int main() {
    FILE *f = fopen("test_rar5.rar", "wb");
    fwrite("Rar!\x1a\x07\x01\x00", 1, 8, f);
    // Add a minimal valid block or just enough to pass detect_archive_type
    fclose(f);
    return 0;
}
