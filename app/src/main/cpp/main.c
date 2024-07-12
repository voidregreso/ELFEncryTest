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
#include <jni.h>

jstring getSectionTable(JNIEnv *env, jobject obj) {
    Dl_info info;
    dladdr((void *)getSectionTable, &info);  // get current function's address

    int fd = open(info.dli_fname, O_RDONLY);
    if (fd < 0) {
        return (*env)->NewStringUTF(env, "Failed to open file");
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0) {
        close(fd);
        return (*env)->NewStringUTF(env, "Failed to get file stats");
    }

    void *file_data = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_data == MAP_FAILED) {
        close(fd);
        return (*env)->NewStringUTF(env, "Failed to map file");
    }

    unsigned char *e_ident = (unsigned char *)file_data;
    int is_64bit = (e_ident[EI_CLASS] == ELFCLASS64);

    void *elf_header = file_data;
    void *section_header = file_data + (is_64bit ? ((Elf64_Ehdr *)elf_header)->e_shoff : ((Elf32_Ehdr *)elf_header)->e_shoff);
    char *section_str_table = file_data + (is_64bit ? ((Elf64_Shdr *)section_header)[((Elf64_Ehdr *)elf_header)->e_shstrndx].sh_offset : ((Elf32_Shdr *)section_header)[((Elf32_Ehdr *)elf_header)->e_shstrndx].sh_offset);

    char *result = (char *)malloc(1024 * 1024);  // 1MB buffer
    if (result == NULL) {
        munmap(file_data, file_stat.st_size);
        close(fd);
        return (*env)->NewStringUTF(env, "Failed to allocate memory");
    }
    result[0] = '\0';

    char buffer[256];
    int shnum = is_64bit ? ((Elf64_Ehdr *)elf_header)->e_shnum : ((Elf32_Ehdr *)elf_header)->e_shnum;

    for (int i = 0; i < shnum; i++) {
        const char *section_name;
        if (is_64bit) {
            Elf64_Shdr *item = &((Elf64_Shdr *)section_header)[i];
            section_name = section_str_table + item->sh_name;
            snprintf(buffer, sizeof(buffer), "shdr64 i = %d, name = %s, sh_addr = %llx, offset = %llx, flags = %llx, size = %llx\n", i, section_name, item->sh_addr, item->sh_offset, item->sh_flags, item->sh_size);
        } else {
            Elf32_Shdr *item = &((Elf32_Shdr *)section_header)[i];
            section_name = section_str_table + item->sh_name;
            snprintf(buffer, sizeof(buffer), "shdr32 i = %d, name = %s, sh_addr = %x, offset = %x, flags = %x, size = %x\n", i, section_name, item->sh_addr, item->sh_offset, item->sh_flags, item->sh_size);
        }
        strcat(result, buffer);
    }

    munmap(file_data, file_stat.st_size);
    close(fd);

    jstring jresult = (*env)->NewStringUTF(env, result);
    free(result);

    return jresult;
}

static JNINativeMethod methods[] = {
    {"getSectionTable", "()Ljava/lang/String;", (void *)getSectionTable}
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    jclass cls = (*env)->FindClass(env, "com/chico/elfencrytest/MainActivity");
    if (cls == NULL) {
        return -1;
    }

    if ((*env)->RegisterNatives(env, cls, methods, sizeof(methods) / sizeof(methods[0])) < 0) {
        return -1;
    }

    return JNI_VERSION_1_6;
}
