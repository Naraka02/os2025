#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ctype.h>
#include "fat32.h"

struct fat32hdr *g_hdr = NULL;
uint32_t *g_fat_table = NULL;
uint32_t g_cluster_size = 0;
uint32_t g_total_clusters = 0;
uint32_t g_data_start_sector = 0;
uint32_t g_entries_per_cluster = 0;

void *map_disk(const char *fname);
void init_globals(struct fat32hdr *hdr);
void print_fat32_info(struct fat32hdr *hdr);
uint32_t *get_fat_table(struct fat32hdr *hdr);
void *get_cluster_data(struct fat32hdr *hdr, uint32_t cluster_num);
uint32_t get_next_cluster(uint32_t *fat_table, uint32_t cluster_num);
void recover_bmp_files(struct fat32hdr *hdr);
void scan_directory(struct fat32hdr *hdr, uint32_t cluster_num, const char *path);
int is_bmp_file(const char *filename);
void extract_bmp_file(struct fat32hdr *hdr, struct fat32dent *entry, const char *path);
void calculate_sha1(const void *data, size_t len, char *sha1_str);
void fat32_name_to_string(const uint8_t *fat_name, char *output);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s fs-image\n", argv[0]);
        exit(1);
    }

    setbuf(stdout, NULL);

    assert(sizeof(struct fat32hdr) == 512); // defensive

    // map disk image to memory
    struct fat32hdr *hdr = map_disk(argv[1]);

    // Initialize global variables
    init_globals(hdr);

    // Print FAT32 filesystem information
    print_fat32_info(hdr);

    // Recover BMP files
    recover_bmp_files(hdr);

    // file system traversal
    munmap(hdr, hdr->BPB_TotSec32 * hdr->BPB_BytsPerSec);
}

void *map_disk(const char *fname) {
    int fd = open(fname, O_RDWR);

    if (fd < 0) {
        perror(fname);
        goto release;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    if (size == -1) {
        perror(fname);
        goto release;
    }

    struct fat32hdr *hdr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (hdr == (void *)-1) {
        goto release;
    }

    close(fd);

    if (hdr->Signature_word != 0xaa55 ||
            hdr->BPB_TotSec32 * hdr->BPB_BytsPerSec != size) {
        fprintf(stderr, "%s: Not a FAT file image\n", fname);
        goto release;
    }
    return hdr;

release:
    if (fd > 0) {
        close(fd);
    }
    exit(1);
}

void init_globals(struct fat32hdr *hdr) {
    g_hdr = hdr;
    g_fat_table = get_fat_table(hdr);
    g_cluster_size = hdr->BPB_BytsPerSec * hdr->BPB_SecPerClus;
    g_total_clusters = (hdr->BPB_TotSec32 - hdr->BPB_RsvdSecCnt - 
                       (hdr->BPB_NumFATs * hdr->BPB_FATSz32)) / hdr->BPB_SecPerClus;
    g_data_start_sector = hdr->BPB_RsvdSecCnt + (hdr->BPB_NumFATs * hdr->BPB_FATSz32);
    g_entries_per_cluster = g_cluster_size / sizeof(struct fat32dent);
}

void print_fat32_info(struct fat32hdr *hdr) {
    printf("=== FAT32 File System Information ===\n");
    
    // Basic filesystem info
    printf("OEM Name: %.8s\n", hdr->BS_OEMName);
    printf("Bytes per Sector: %u\n", hdr->BPB_BytsPerSec);
    printf("Sectors per Cluster: %u\n", hdr->BPB_SecPerClus);
    printf("Reserved Sectors: %u\n", hdr->BPB_RsvdSecCnt);
    printf("Number of FATs: %u\n", hdr->BPB_NumFATs);
    
    // Volume information
    printf("Total Sectors: %u\n", hdr->BPB_TotSec32);
    printf("Sectors per FAT: %u\n", hdr->BPB_FATSz32);
    printf("Root Directory Cluster: %u\n", hdr->BPB_RootClus);
    printf("Volume ID: 0x%08X\n", hdr->BS_VolID);
    printf("Volume Label: %.11s\n", hdr->BS_VolLab);
    printf("File System Type: %.8s\n", hdr->BS_FilSysType);
    
    // Calculated values (using global variables)
    uint32_t fat_start_sector = hdr->BPB_RsvdSecCnt;
    
    printf("\n=== Calculated Information ===\n");
    printf("Bytes per Cluster: %u\n", g_cluster_size);
    printf("Total Clusters: %u\n", g_total_clusters);
    printf("FAT Start Sector: %u\n", fat_start_sector);
    printf("Data Start Sector: %u\n", g_data_start_sector);
    printf("Total Size: %u bytes (%.2f MB)\n", 
           hdr->BPB_TotSec32 * hdr->BPB_BytsPerSec,
           (double)(hdr->BPB_TotSec32 * hdr->BPB_BytsPerSec) / (1024 * 1024));
    
    printf("\n=== Boot Signature ===\n");
    printf("Signature: 0x%04X %s\n", hdr->Signature_word, 
           hdr->Signature_word == 0xaa55 ? "(Valid)" : "(Invalid)");
    
    printf("\n");
}

uint32_t *get_fat_table(struct fat32hdr *hdr) {
    // FAT table starts after reserved sectors
    uint8_t *disk = (uint8_t *)hdr;
    uint32_t fat_offset = hdr->BPB_RsvdSecCnt * hdr->BPB_BytsPerSec;
    return (uint32_t *)(disk + fat_offset);
}

void *get_cluster_data(struct fat32hdr *hdr, uint32_t cluster_num) {
    if (cluster_num < 2) {
        return NULL; // cluster 0 and 1 are reserved
    }
    
    uint8_t *disk = (uint8_t *)hdr;
    uint32_t cluster_offset = g_data_start_sector * hdr->BPB_BytsPerSec + 
                              (cluster_num - 2) * g_cluster_size;
    
    return disk + cluster_offset;
}

uint32_t get_next_cluster(uint32_t *fat_table, uint32_t cluster_num) {
    uint32_t next_cluster = fat_table[cluster_num] & 0x0FFFFFFF;
    
    if (next_cluster >= 0x0FFFFFF8) {
        return 0;
    }
    
    return next_cluster;
}

// 将FAT32文件名转换为普通字符串
void fat32_name_to_string(const uint8_t *fat_name, char *output) {
    int i, j = 0;
    
    // 复制文件名部分（前8个字符）
    for (i = 0; i < 8 && fat_name[i] != ' '; i++) {
        output[j++] = tolower(fat_name[i]);
    }
    
    // 检查是否有扩展名
    if (fat_name[8] != ' ') {
        output[j++] = '.';
        for (i = 8; i < 11 && fat_name[i] != ' '; i++) {
            output[j++] = tolower(fat_name[i]);
        }
    }
    
    output[j] = '\0';
}

// 检查是否是BMP文件
int is_bmp_file(const char *filename) {
    size_t len = strlen(filename);
    if (len < 4) return 0;
    
    const char *ext = filename + len - 4;
    return (strcasecmp(ext, ".bmp") == 0);
}

// 计算SHA1哈希值 (使用外部sha1sum工具)
void calculate_sha1(const void *data, size_t len, char *sha1_str) {
    // 创建临时文件
    char temp_filename[] = "/tmp/fsrecov_temp_XXXXXX";
    int temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1) {
        strcpy(sha1_str, "error_creating_temp_file");
        return;
    }
    
    // 写入数据到临时文件
    ssize_t bytes_written = write(temp_fd, data, len);
    close(temp_fd);
    
    if (bytes_written != (ssize_t)len) {
        unlink(temp_filename);
        strcpy(sha1_str, "error_writing_temp_file");
        return;
    }
    
    // 执行sha1sum命令
    char command[512];
    snprintf(command, sizeof(command), "sha1sum %s", temp_filename);
    
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        unlink(temp_filename);
        strcpy(sha1_str, "error_executing_sha1sum");
        return;
    }
    
    // 读取sha1sum的输出
    char result[128];
    if (fgets(result, sizeof(result), pipe) != NULL) {
        // sha1sum输出格式: "hash  filename"，我们只要hash部分
        char *space = strchr(result, ' ');
        if (space) {
            *space = '\0';
        }
        strncpy(sha1_str, result, 40);
        sha1_str[40] = '\0';
    } else {
        strcpy(sha1_str, "error_reading_sha1sum_output");
    }
    
    pclose(pipe);
    unlink(temp_filename);
}

// 提取BMP文件
void extract_bmp_file(struct fat32hdr *hdr, struct fat32dent *entry, const char *path) {
    // 获取文件大小和起始cluster
    uint32_t file_size = entry->DIR_FileSize;
    uint32_t start_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
    
    if (file_size == 0 || start_cluster < 2) {
        return;
    }
    
    // 分配内存来存储文件内容
    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        printf("Memory allocation failed for file extraction\n");
        return;
    }
    
    // 读取文件的所有cluster
    uint32_t current_cluster = start_cluster;
    uint32_t bytes_read = 0;
    
    while (current_cluster >= 2 && bytes_read < file_size) {
        void *cluster_data = get_cluster_data(hdr, current_cluster);
        if (!cluster_data) break;
        
        uint32_t bytes_to_copy = (file_size - bytes_read > g_cluster_size) ? 
                                g_cluster_size : (file_size - bytes_read);
        
        memcpy(file_data + bytes_read, cluster_data, bytes_to_copy);
        bytes_read += bytes_to_copy;
        
        current_cluster = get_next_cluster(g_fat_table, current_cluster);
    }
    
    // 验证是否是有效的BMP文件（检查BMP文件头）
    if (bytes_read >= 14 && file_data[0] == 'B' && file_data[1] == 'M') {
        // 生成文件名
        char filename[256];
        fat32_name_to_string(entry->DIR_Name, filename);
        
        // 计算SHA1
        char sha1_str[41]; // SHA1是40个字符 + null终止符
        calculate_sha1(file_data, bytes_read, sha1_str);
        
        // 创建输出目录
        mkdir("recovered_bmps", 0755);
        
        // 生成输出文件路径
        char output_path[512];
        snprintf(output_path, sizeof(output_path), "recovered_bmps/%s_%s.bmp", 
                sha1_str, filename);
        
        // 写入文件
        FILE *outfile = fopen(output_path, "wb");
        if (outfile) {
            fwrite(file_data, 1, bytes_read, outfile);
            fclose(outfile);
            
            printf("Recovered BMP: %s\n", filename);
            printf("  Path: %s%s\n", path, filename);
            printf("  Size: %u bytes\n", bytes_read);
            printf("  SHA1: %s\n", sha1_str);
            printf("  Output: %s\n\n", output_path);
        } else {
            printf("Failed to write recovered file: %s\n", output_path);
        }
    }
    
    free(file_data);
}

void scan_directory(struct fat32hdr *hdr, uint32_t cluster_num, const char *path) {
    if (cluster_num < 2) return;
    
    uint32_t current_cluster = cluster_num;
    
    while (current_cluster >= 2) {
        void *cluster_data = get_cluster_data(hdr, current_cluster);
        if (!cluster_data) break;
        
        struct fat32dent *entries = (struct fat32dent *)cluster_data;
        
        for (uint32_t i = 0; i < g_entries_per_cluster; i++) {
            struct fat32dent *entry = &entries[i];
            
            // 跳过空条目和删除的文件
            if (entry->DIR_Name[0] == 0x00) break;
            if (entry->DIR_Name[0] == 0xE5) continue;
            
            // 跳过长文件名条目
            if ((entry->DIR_Attr & 0x0F) == 0x0F) continue;
            
            // 跳过"."和".."条目
            if (entry->DIR_Name[0] == '.') continue;
            
            char filename[256];
            fat32_name_to_string(entry->DIR_Name, filename);
            
            if (entry->DIR_Attr & ATTR_DIRECTORY) {
                // 递归扫描子目录
                if (strcmp(filename, ".") != 0 && strcmp(filename, "..") != 0) {
                    uint32_t subdir_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
                    char new_path[512];
                    snprintf(new_path, sizeof(new_path), "%s%s/", path, filename);
                    scan_directory(hdr, subdir_cluster, new_path);
                }
            } else {
                // 检查是否是BMP文件
                if (is_bmp_file(filename)) {
                    extract_bmp_file(hdr, entry, path);
                }
            }
        }
        
        current_cluster = get_next_cluster(g_fat_table, current_cluster);
    }
}

// 恢复BMP文件的主函数
void recover_bmp_files(struct fat32hdr *hdr) {
    printf("=== BMP File Recovery ===\n");
    printf("Scanning filesystem for BMP files...\n\n");
    
    // 从根目录开始扫描
    scan_directory(hdr, hdr->BPB_RootClus, "/");
    
    printf("BMP file recovery completed.\n");
    printf("All recovered files are saved in the 'recovered_bmps' directory.\n\n");
}
