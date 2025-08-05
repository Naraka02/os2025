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
void extract_bmp(uint32_t cluster_num);
uint32_t find_next_cluster(uint32_t current_cluster);
uint32_t get_next_cluster(uint32_t cluster);
int is_bmp_extension(const char *filename);
int is_directory_cluster(uint32_t cluster);

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

uint32_t find_next_cluster(uint32_t current_cluster) {
    void *current_data = get_cluster_data(g_hdr, current_cluster);
    if (!current_data) return current_cluster + 1;
    
    uint8_t *current_bytes = (uint8_t *)current_data;
    
    uint32_t pixels_per_row = 21;  // 21 pixels * 3 bytes = 63 bytes per row
    uint32_t bytes_per_row = pixels_per_row * 3;
    uint32_t last_row_start = g_cluster_size - bytes_per_row;
    if (last_row_start >= g_cluster_size) last_row_start = g_cluster_size - bytes_per_row;
    
    uint32_t best_cluster = current_cluster + 1;
    uint32_t min_diff = UINT32_MAX;

    uint32_t search_range[] = {1, 2, 3, 4, 5, -1, -2, -3, 6, 7, 8, 9, 10, -4, -5, 
                              11, 12, 13, 14, 15, -6, -7, -8, 16, 17, 18, 19, 20, 
                              -9, -10, 21, 22, 23, 24, 25, -11, -12, -13, 26, 27, 
                              28, 29, 30, -14, -15, 31, 32, 33, 34, 35, -16, -17, 
                              -18, 36, 37, 38, 39, 40, -19, -20};
    int search_count = sizeof(search_range) / sizeof(search_range[0]);
    
    for (int i = 0; i < search_count; i++) {
        int32_t offset = search_range[i];
        uint32_t candidate = (offset > 0) ? current_cluster + offset : 
                           (current_cluster >= -offset) ? current_cluster + offset : 0;
        
        if (candidate < 2 || candidate >= g_total_clusters + 2) continue;
        
        void *candidate_data = get_cluster_data(g_hdr, candidate);
        if (!candidate_data) continue;
        
        uint8_t *candidate_bytes = (uint8_t *)candidate_data;

        uint32_t total_diff = 0;
        uint32_t valid_pixels = 0;
        
        for (uint32_t j = 0; j < pixels_per_row; j++) {
            uint32_t current_offset = last_row_start + (j * 3);
            uint32_t candidate_offset = j * 3;
            
            if (current_offset + 2 < g_cluster_size && candidate_offset + 2 < g_cluster_size) {
                uint8_t curr_r = current_bytes[current_offset];
                uint8_t curr_g = current_bytes[current_offset + 1];
                uint8_t curr_b = current_bytes[current_offset + 2];
                
                uint8_t cand_r = candidate_bytes[candidate_offset];
                uint8_t cand_g = candidate_bytes[candidate_offset + 1];
                uint8_t cand_b = candidate_bytes[candidate_offset + 2];
                
                uint32_t diff = abs((int)curr_r - (int)cand_r) + 
                               abs((int)curr_g - (int)cand_g) + 
                               abs((int)curr_b - (int)cand_b);
                
                total_diff += diff;
                valid_pixels++;
            }
        }
        
        if (valid_pixels > 0) {
            uint32_t avg_diff = total_diff / valid_pixels;

            // Check for non-zero RGB data
            int non_zero_count = 0;
            for (uint32_t k = 0; k < pixels_per_row && k * 3 + 2 < g_cluster_size; k++) {
                if (candidate_bytes[k * 3] != 0 || 
                    candidate_bytes[k * 3 + 1] != 0 || 
                    candidate_bytes[k * 3 + 2] != 0) {
                    non_zero_count++;
                }
            }
            
            if (avg_diff < min_diff && non_zero_count > 3) {
                min_diff = avg_diff;
                best_cluster = candidate;
            }
        }
    }
    
    // Increase threshold for RGB comparison (3 components * max 255 diff each = 765 max)
    if (min_diff < 300) {
        return best_cluster;
    }
    
    return current_cluster + 1;
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

void extract_bmp(uint32_t cluster_num) {
    void *cluster_data = get_cluster_data(g_hdr, cluster_num);
    if (!cluster_data) return;

    struct fat32dent *entries = (struct fat32dent *)cluster_data;
    
    for (uint32_t i = 0; i < g_entries_per_cluster; i++) {
        struct fat32dent *entry = &entries[i];
        
        if (entry->DIR_Name[0] == 0x00) break;
        
        // Check for standard entry
        if ((entry->DIR_Attr & 0x0F) == 0x0F) continue;
        
        uint32_t start_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
        uint32_t file_size = entry->DIR_FileSize;
        
        // Collect LFN entry backwards
        char long_filename[256] = "";
        int lfn_start = i - 1;
        
        while (lfn_start >= 0) {
            struct fat32dent *lfn_entry = &entries[lfn_start];
            
            // Stop if not LFN entry
            if ((lfn_entry->DIR_Attr & 0x0F) != 0x0F) break;
            
            uint8_t *lfn_data = (uint8_t *)lfn_entry;
            uint8_t is_last = (lfn_data[0] & 0x40) ? 1 : 0;
            
            char partial_name[256];
            extract_single_lfn(lfn_data, partial_name);
            
            if (strlen(long_filename) == 0) {
                strcpy(long_filename, partial_name);
            } else {
                char temp[256];
                strcpy(temp, long_filename);
                strcat(temp, partial_name);
                strcpy(long_filename, temp);
            }
            
            if (is_last) break;
            lfn_start--;
        }
        
        if (!is_bmp_extension(long_filename)) continue;
        if (start_cluster < 2 || file_size == 0) continue;
        
        uint8_t *file_data = malloc(file_size);
        if (!file_data) continue;
        
        uint32_t bytes_read = 0;
        uint32_t current_cluster = start_cluster;
        
        while (bytes_read < file_size && current_cluster >= 2 && current_cluster < g_total_clusters + 2) {
            void *cluster_data_file = get_cluster_data(g_hdr, current_cluster);
            if (!cluster_data_file) break;
            
            uint32_t bytes_to_copy = (file_size - bytes_read > g_cluster_size) ? 
                                    g_cluster_size : (file_size - bytes_read);
            
            memcpy(file_data + bytes_read, cluster_data_file, bytes_to_copy);
            bytes_read += bytes_to_copy;
            
            current_cluster = find_next_cluster(current_cluster);
        }
        
        if (file_data[0] == 'B' && file_data[1] == 'M') {
            char sha1_str[41];
            calculate_sha1(file_data, bytes_read, sha1_str);
            printf("%s  %s\n", sha1_str, long_filename);
            fflush(stdout);
        }
        
        free(file_data);
    }
}

void carve_bmps(struct fat32hdr *hdr) {
    for (uint32_t cluster = 2; cluster < g_total_clusters + 2; cluster++) {
        if (!is_directory_cluster(cluster)) {
            continue;
        }

        void *cluster_data = get_cluster_data(hdr, cluster);
        if (!cluster_data) continue;
        
        extract_bmp(cluster);
    }
}

int is_directory_cluster(uint32_t cluster) {
    void *cluster_data = get_cluster_data(g_hdr, cluster);
    if (!cluster_data) return 0;

    uint8_t *data = (uint8_t *)cluster_data;
    int bmp_count = 0;
    
    // Search for 'bmp' string in the cluster (case insensitive)
    for (uint32_t i = 0; i < g_cluster_size - 2; i++) {
        if ((data[i] == 'b' || data[i] == 'B') &&
            (data[i+1] == 'm' || data[i+1] == 'M') &&
            (data[i+2] == 'p' || data[i+2] == 'P')) {
            bmp_count++;
        }
    }
    
    return (bmp_count >= 2);
}