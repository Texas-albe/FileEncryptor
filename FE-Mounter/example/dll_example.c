/* FE-Mounter 示例：用 libvdisk（vdisk.dll）C ABI 读一个加密库。
 *
 * 演示 §5.2 契约的典型用法：open → unlock → readdir → getattr → read → close。
 * 链接 vdisk.lib（vdisk.dll 的导入库）；运行时需 vdisk.dll 在同目录或 PATH。
 * 第三方应用消费 libvdisk 的最小完整示例。
 *
 * 编译（MSVC，x64）：
 *   cl /nologo /std:c17 /I <CLI>\include dll_example.c /link vdisk.lib /OUT:dll_example.exe
 * 运行：
 *   dll_example.exe <库目录> <口令>
 */
#include "vdisk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_tree(VDiskHandle* h, const char* vpath) {
    uint64_t count = 0;
    if (vdisk_readdir(h, vpath, NULL, &count) != VDISK_OK) return;
    if (count == 0) return;
    VDiskEntry* entries = (VDiskEntry*)calloc(count, sizeof(VDiskEntry));
    if (!entries) return;
    if (vdisk_readdir(h, vpath, &entries, &count) == VDISK_OK) {
        for (uint64_t i = 0; i < count; i++) {
            char child[512];
            snprintf(child, sizeof child, "%s/%s",
                     strcmp(vpath, "/") == 0 ? "" : vpath, entries[i].name);
            if (entries[i].is_dir) {
                printf("  [DIR ] %s\n", child);
                print_tree(h, child);
            } else {
                printf("  [FILE] %-40s %8llu bytes\n", child, (unsigned long long)entries[i].size);
            }
        }
    }
    free(entries);
}

int main(int argc, char** argv) {
    if (argc < 3) { printf("用法: dll_example <库目录> <口令>\n"); return 1; }
    const char* vault = argv[1];
    const char* pass  = argv[2];

    VDiskHandle* h = vdisk_open(vault);
    if (!h) { printf("vdisk_open 失败（不是有效库?）\n"); return 2; }

    if (vdisk_unlock(h, pass, 0) != VDISK_OK) {
        printf("vdisk_unlock 失败（口令错误?）: %s\n", vdisk_strerror(VDISK_E_AUTH));
        vdisk_close(h); return 3;
    }
    printf("库已解锁: %s\n", vault);
    printf("目录树:\n");
    print_tree(h, "/");

    /* 读第一个文件的前 32 字节（§1 随机块读，O(1) 定位） */
    uint64_t count = 0;
    vdisk_readdir(h, "/", NULL, &count);
    if (count > 0) {
        VDiskEntry* e = (VDiskEntry*)calloc(count, sizeof(VDiskEntry));
        if (e && vdisk_readdir(h, "/", &e, &count) == VDISK_OK) {
            char vpath[512];
            snprintf(vpath, sizeof vpath, "/%s", e[0].name);
            unsigned char buf[32] = {0};
            uint64_t len = sizeof buf;
            if (vdisk_read_file(h, vpath, 0, buf, &len) == VDISK_OK) {
                printf("读 %s 前 %llu 字节: ", vpath, (unsigned long long)len);
                for (uint64_t i = 0; i < len; i++) printf("%02x", buf[i]);
                printf("\n");
            }
        }
        free(e);
    }

    vdisk_lock(h);        /* 锁定：全清 KEK/索引密钥 */
    vdisk_close(h);
    printf("已锁定并关闭。\n");
    return 0;
}
