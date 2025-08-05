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
uint32_t *get_fat_table(struct fat32hdr *hdr);
void *get_cluster_data(struct fat32hdr *hdr, uint32_t cluster_num);
void calculate_sha1(const void *data, size_t len, char *sha1_str);
void carve_bmps(struct fat32hdr *hdr);
void extract_bmp(void *cluster_data, uint32_t cluster_num);
int is_bmp_extension(const char *filename);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s fs-image\n", argv[0]);
        exit(1);
    }

    setbuf(stdout, NULL);

    assert(sizeof(struct fat32hdr) == 512); // defensive

    // map disk image to memory
    struct fat32hdr *hdr = map_disk(argv[1]);

    init_globals(hdr);
    
    // Carve directory information first (recover filenames)
    carve_bmps(hdr);

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

void calculate_sha1(const void *data, size_t len, char *sha1_str) {
    char temp_filename[] = "/tmp/fsrecov_temp_XXXXXX";
    int temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1) {
        strcpy(sha1_str, "error_creating_temp_file");
        return;
    }
    
    // Write data to the temporary file
    ssize_t bytes_written = write(temp_fd, data, len);
    close(temp_fd);
    
    if (bytes_written != (ssize_t)len) {
        unlink(temp_filename);
        strcpy(sha1_str, "error_writing_temp_file");
        return;
    }
    
    char command[512];
    snprintf(command, sizeof(command), "sha1sum %s", temp_filename);
    
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        unlink(temp_filename);
        strcpy(sha1_str, "error_executing_sha1sum");
        return;
    }
    
    char result[128];
    if (fgets(result, sizeof(result), pipe) != NULL) {
        // sha1sum output format: "hash  filename", take the hash part
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


void extract_single_lfn(uint8_t *lfn_data, char *partial_name) {
    int char_count = 0;
    
    // Characters are stored at offsets 1-10, 14-25, 28-31
    for (int i = 1; i <= 10; i += 2) {
        if (lfn_data[i] != 0 && lfn_data[i] != 0xFF && char_count < 255) {
            partial_name[char_count++] = lfn_data[i];
        }
    }
    for (int i = 14; i <= 25; i += 2) {
        if (lfn_data[i] != 0 && lfn_data[i] != 0xFF && char_count < 255) {
            partial_name[char_count++] = lfn_data[i];
        }
    }
    for (int i = 28; i <= 31; i += 2) {
        if (lfn_data[i] != 0 && lfn_data[i] != 0xFF && char_count < 255) {
            partial_name[char_count++] = lfn_data[i];
        }
    }
    
    partial_name[char_count] = '\0';
}

int is_bmp_extension(const char *filename) {
    int len = strlen(filename);
    if (len < 4) return 0;
    
    const char *ext = filename + len - 4;
    return (strcasecmp(ext, ".bmp") == 0);
}

void extract_bmp(void *cluster_data, uint32_t cluster_num) {
    struct fat32dent *entries = (struct fat32dent *)cluster_data;
    char filename[256] = "";
    
    for (uint32_t i = 0; i < g_entries_per_cluster; i++) {
        struct fat32dent *entry = &entries[i];
        uint8_t *entry_data = (uint8_t *)entry;
        
        // Skip empty entries
        if (entry->DIR_Name[0] == 0x00) break;
        
        // Check if this is an LFN entry
        if ((entry->DIR_Attr & 0x0F) == 0x0F) {
            uint8_t is_last = (entry_data[0] & 0x40) ? 1 : 0;
            
            char partial_name[256];
            extract_single_lfn(entry_data, partial_name);
            
            // If this is the first LFN entry (highest sequence number), start fresh
            if (is_last) {
                strcpy(filename, partial_name);
            } else {
                // Prepend this fragment to build the complete name
                char temp[256];
                strcpy(temp, partial_name);
                strcat(temp, filename);
                strcpy(filename, temp);
            }
        } else  {      
            uint32_t start_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
            uint32_t file_size = entry->DIR_FileSize;

            if (is_bmp_extension(filename)) {
                if (start_cluster >= 2 && file_size > 0) {
                    uint8_t *file_data = malloc(file_size);
                    
                    uint32_t bytes_read = 0;
                    uint32_t current_cluster = start_cluster;
                        
                    // Read clusters sequentially 
                    while (bytes_read < file_size && current_cluster >= 2 && current_cluster < g_total_clusters + 2) {
                        void *cluster_data = get_cluster_data(g_hdr, current_cluster);
                        if (!cluster_data) break;
                        
                        uint32_t bytes_to_copy = (file_size - bytes_read > g_cluster_size) ? 
                                                g_cluster_size : (file_size - bytes_read);
                        
                        memcpy(file_data + bytes_read, cluster_data, bytes_to_copy);
                        bytes_read += bytes_to_copy;
                            
                        current_cluster++;
                    }
                        
                    if (bytes_read >= file_size && bytes_read >= 14 && 
                        file_data[0] == 'B' && file_data[1] == 'M') {
                        char sha1_str[41];
                        calculate_sha1(file_data, bytes_read, sha1_str);
                        printf("%s  %s\n", sha1_str, filename);
                    }
                        
                    free(file_data);
                }
            }
            
            filename[0] = '\0';
        }
    }
}

void carve_bmps(struct fat32hdr *hdr) {
    for (uint32_t cluster = 2; cluster < g_total_clusters + 2; cluster++) {
        void *cluster_data = get_cluster_data(hdr, cluster);
        if (!cluster_data) continue;
        
        struct fat32dent *entries = (struct fat32dent *)cluster_data;
        
        // Check for lfn entries
        int has_lfn_entries = 0;
        
        for (uint32_t i = 0; i < g_entries_per_cluster && i < 4; i++) {
            struct fat32dent *entry = &entries[i];
            
            // Skip empty entries
            if (entry->DIR_Name[0] == 0x00) break;
            
            // Check for LFN entries or valid directory entries
            if ((entry->DIR_Attr & 0x0F) == 0x0F ||  // LFN entry
                (entry->DIR_Name[0] != 0xE5 && 
                 (entry->DIR_Attr & (ATTR_DIRECTORY | ATTR_ARCHIVE)))) {
                has_lfn_entries = 1;
                break;
            }
        }
        
        if (has_lfn_entries) {
            extract_bmp(cluster_data, cluster);
        }
    }
}