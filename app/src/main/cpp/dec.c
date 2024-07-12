#include <jni.h>
#include "utils.h"
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <unistd.h>
#include <errno.h>

#define LOG_TAG "ELFEncryption"
#define LOG_I(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOG_W(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define SH_UTIL_ALIGN_START(x, align) ((uintptr_t)(x) & ~((uintptr_t)(align)-1))
#define SH_UTIL_ALIGN_END(x, align)   (((uintptr_t)(x) + (uintptr_t)(align)-1) & ~((uintptr_t)(align)-1))
#define SH_UTIL_PAGE_START(x) SH_UTIL_ALIGN_START(x, 0x1000)
#define SH_UTIL_PAGE_END(x)   SH_UTIL_ALIGN_END(x, 0x1000)

#if defined(__aarch64__) || defined(__x86_64__) || defined(__mips64)
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
#endif

static const unsigned char key[] = "JuanCarlos@41273JuanCarlos@41273"; // 256-bit key
static const unsigned char iv[16] = {0}; // 128-bit IV, all zero for simplicity

__attribute__((constructor(101))) // Make it appear in init_array and be executed before JNI_OnLoad()
__attribute__((section(".preload")))
void resumeCode() {
    LOG_I("We are ready to decrypt the native code!");

    void* handle = dlopen("libcryutil.so", RTLD_NOW);
    if (!handle) {
        LOG_E("Failed to load libcryutil.so: %s", dlerror());
        exit(-1);
    }

    Dl_info info;
    if (!dladdr((void*)resumeCode, &info)) {
        LOG_E("dladdr failed");
        return;
    }

    int fd = open(info.dli_fname, O_RDONLY);
    if (fd < 0) {
        LOG_E("Failed to open file: %s", info.dli_fname);
        return;
    } else LOG_W("SO file: %s opened at %p", info.dli_fname, info.dli_fbase);

    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0) {
        LOG_E("Failed to get file stats");
        close(fd);
        return;
    }

    void *file_data = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_data == MAP_FAILED) {
        LOG_E("Failed to map file");
        close(fd);
        return;
    }

    Elf_Ehdr *elf_header = (Elf_Ehdr *)file_data;
    Elf_Shdr *sectionHeader = (Elf_Shdr *)(file_data + elf_header->e_shoff);
    char *section_str_table = file_data + ((Elf_Shdr *)sectionHeader)[((Elf_Ehdr *)elf_header)->e_shstrndx].sh_offset;

    for(int i = 0 ; i < elf_header->e_shnum ; i++) {
        Elf_Shdr *item = sectionHeader + i;
        const char *section_name = section_str_table + item->sh_name;
        if(strcmp(section_name, ".text") != 0) {
            continue;
        }

        char* ptr = (char*)info.dli_fbase + item->sh_addr;
        uintptr_t start = SH_UTIL_PAGE_START((uintptr_t)ptr);
        uintptr_t end = SH_UTIL_PAGE_END((uintptr_t)ptr + item->sh_size - 1);
        LOG_I("SECTION %s, sh_addr=0x%llx, start_addr=0x%llx, end_addr=0x%llx!", section_name, item->sh_addr, start, end);

        if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOG_E("mprotect failed: %s", strerror(errno));
            munmap(file_data, file_stat.st_size);
            close(fd);
            return;
        } else LOG_W("Mprotect alignment completed!");

        decrypt((unsigned char*)ptr, item->sh_size, key, iv);
        LOG_I("Decrypted .text section length: %lu", item->sh_size);
        // LOG_I("Decrypted .text section first 64 bytes: %s", bytesToHex((unsigned char*)ptr, 64));

        if (mprotect((void *)start, end - start, PROT_READ | PROT_EXEC) != 0) {
            LOG_E("mprotect reset failed: %s", strerror(errno));
            munmap(file_data, file_stat.st_size);
            close(fd);
            return;
        } else LOG_W("Mprotect restore completed!");
        my_clear_cache((void*)start, (void*)end);
        break;
    }

    munmap(file_data, file_stat.st_size);
    close(fd);

    LOG_I("All procedures completed!");
}
