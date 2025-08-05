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
void extract_bmp_file(struct fat32hdr *hdr, struct fat32dent *entry, const char *path, const char *filename);
void calculate_sha1(const void *data, size_t len, char *sha1_str);
void fat32_name_to_string(const uint8_t *fat_name, char *output);
void get_long_filename(struct fat32dent *entries, int entry_index, char *long_name);
void recover_bmps(struct fat32hdr *hdr);
int extract_bmp_from_cluster(struct fat32hdr *hdr, uint32_t cluster_num, uint32_t offset_in_cluster);
void try_extract_filename_from_bmp(uint8_t *bmp_data, uint32_t bmp_size, char *extracted_name);
void scan_for_deleted_entries(struct fat32hdr *hdr);
void scan_deleted_in_cluster(struct fat32hdr *hdr, uint32_t cluster_num);
void extract_deleted_bmp_file(struct fat32hdr *hdr, struct fat32dent *entry, const char *filename);

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
    
    // First try to find deleted directory entries
    scan_for_deleted_entries(hdr);
    
    // Then scan for BMP signatures in data area
    recover_bmps(hdr);

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

uint32_t get_next_cluster(uint32_t *fat_table, uint32_t cluster_num) {
    uint32_t next_cluster = fat_table[cluster_num] & 0x0FFFFFFF;
    
    if (next_cluster >= 0x0FFFFFF8) {
        return 0;
    }
    
    return next_cluster;
}

// convert FAT32 filename to a string
void fat32_name_to_string(const uint8_t *fat_name, char *output) {
    int i, j = 0;

    // Copy the filename part (first 8 characters)
    for (i = 0; i < 8 && fat_name[i] != ' '; i++) {
        output[j++] = tolower(fat_name[i]);
    }
    
    // Add a dot if there is an extension
    if (fat_name[8] != ' ') {
        output[j++] = '.';
        for (i = 8; i < 11 && fat_name[i] != ' '; i++) {
            output[j++] = tolower(fat_name[i]);
        }
    }
    
    output[j] = '\0';
}

// Extract long filename from LFN entries
void get_long_filename(struct fat32dent *entries, int entry_index, char *long_name) {
    long_name[0] = '\0';
    
    // Look backwards for LFN entries
    int lfn_index = entry_index - 1;
    char temp_name[256] = {0};
    int total_chars = 0;
    
    // Collect LFN entries in reverse order
    while (lfn_index >= 0) {
        struct fat32dent *lfn_entry = &entries[lfn_index];
        
        // Check if this is an LFN entry
        if ((lfn_entry->DIR_Attr & 0x0F) != 0x0F) {
            break;
        }
        
        // Extract characters from LFN entry
        uint8_t *lfn_data = (uint8_t *)lfn_entry;
        
        // Extract Unicode characters and convert to ASCII (simplified)
        // Characters are stored at offsets 1-10, 14-25, 28-31
        for (int i = 1; i <= 10; i += 2) {
            if (lfn_data[i] != 0 && lfn_data[i] != 0xFF) {
                temp_name[total_chars++] = lfn_data[i];
            }
        }
        for (int i = 14; i <= 25; i += 2) {
            if (lfn_data[i] != 0 && lfn_data[i] != 0xFF) {
                temp_name[total_chars++] = lfn_data[i];
            }
        }
        for (int i = 28; i <= 31; i += 2) {
            if (lfn_data[i] != 0 && lfn_data[i] != 0xFF) {
                temp_name[total_chars++] = lfn_data[i];
            }
        }
        
        // Check if this is the last LFN entry
        if (lfn_data[0] & 0x40) {
            break;
        }
        
        lfn_index--;
    }
    
    // Reverse the collected name and copy to output
    if (total_chars > 0) {
        for (int i = 0; i < total_chars; i++) {
            long_name[i] = temp_name[i];
        }
        long_name[total_chars] = '\0';
    }
}

int is_bmp_file(const char *filename) {
    size_t len = strlen(filename);
    if (len < 4) return 0;
    
    const char *ext = filename + len - 4;
    return (strcasecmp(ext, ".bmp") == 0);
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

void extract_bmp_file(struct fat32hdr *hdr, struct fat32dent *entry, const char *path, const char *filename) {
    uint32_t file_size = entry->DIR_FileSize;
    uint32_t start_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
    
    if (file_size == 0 || start_cluster < 2) {
        return;
    }
    
    // Store file data in memory
    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        printf("Memory allocation failed for file extraction\n");
        return;
    }
    
    // Read clusters until the end of the file
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
    
    // Check BMP header
    if (bytes_read >= 14 && file_data[0] == 'B' && file_data[1] == 'M') {
        // Calculate SHA1 hash
        char sha1_str[41]; // 40 characters + null terminator
        calculate_sha1(file_data, bytes_read, sha1_str);

        printf("%s  %s\n", sha1_str, filename);
        fflush(stdout);
        
        // // Create output directory
        // mkdir("recovered_bmps", 0755);
        
        // // Generate output file path using the provided filename
        // char output_path[512];
        // snprintf(output_path, sizeof(output_path), "recovered_bmps/%s",  filename);
        
        // // Write the recovered BMP file
        // FILE *outfile = fopen(output_path, "wb");
        // if (outfile) {
        //     fwrite(file_data, 1, bytes_read, outfile);
        //     fclose(outfile);
        // } else {
        //     printf("Failed to write recovered file: %s\n", output_path);
        // }
        
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
            
            // Skip empty entries and deleted files
            if (entry->DIR_Name[0] == 0x00) break;
            if (entry->DIR_Name[0] == 0xE5) continue;
            
            // Skip long file name entries (we'll process them when we hit the actual file entry)
            if ((entry->DIR_Attr & 0x0F) == 0x0F) continue;
            
            // Skip "." and ".." entries
            if (entry->DIR_Name[0] == '.') continue;
            
            char filename[256];
            char long_filename[256];
            
            // Try to get long filename first
            get_long_filename(entries, i, long_filename);
            
            if (strlen(long_filename) > 0) {
                strcpy(filename, long_filename);
            } else {
                // Fall back to short filename
                fat32_name_to_string(entry->DIR_Name, filename);
            }
            
            if (entry->DIR_Attr & ATTR_DIRECTORY) {
                // Scan subdirectory
                if (strcmp(filename, ".") != 0 && strcmp(filename, "..") != 0) {
                    uint32_t subdir_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
                    char new_path[512];
                    snprintf(new_path, sizeof(new_path), "%s%s/", path, filename);
                    scan_directory(hdr, subdir_cluster, new_path);
                }
            } else {
                if (is_bmp_file(filename)) {
                    extract_bmp_file(hdr, entry, path, filename);
                }
            }
        }
        
        current_cluster = get_next_cluster(g_fat_table, current_cluster);
    }
}

// Extract BMP file starting from a specific cluster and offset
int extract_bmp_from_cluster(struct fat32hdr *hdr, uint32_t cluster_num, uint32_t offset_in_cluster) {
    void *cluster_data = get_cluster_data(hdr, cluster_num);
    if (!cluster_data) return 0;
    
    uint8_t *bmp_start = (uint8_t *)cluster_data + offset_in_cluster;
    
    // Check BMP signature
    if (bmp_start[0] != 'B' || bmp_start[1] != 'M') {
        return 0;
    }
    
    // Get file size from BMP header (bytes 2-5)
    uint32_t bmp_size = *(uint32_t *)(bmp_start + 2);
    
    // Sanity check for BMP size (should be reasonable)
    if (bmp_size < 54 || bmp_size > 100 * 1024 * 1024) { // Min 54 bytes, max 100MB
        return 0;
    }
    
    // Additional BMP header validation
    uint32_t data_offset = *(uint32_t *)(bmp_start + 10);
    uint32_t header_size = *(uint32_t *)(bmp_start + 14);
    
    if (data_offset < 54 || header_size < 40) {
        return 0;
    }
    
    // Allocate memory for the entire BMP file
    uint8_t *bmp_data = malloc(bmp_size);
    if (!bmp_data) {
        printf("Memory allocation failed for BMP recovery\n");
        return 0;
    }
    
    // Read the BMP data across clusters
    uint32_t bytes_read = 0;
    uint32_t current_cluster = cluster_num;
    uint32_t current_offset = offset_in_cluster;
    
    while (bytes_read < bmp_size && current_cluster >= 2) {
        void *current_cluster_data = get_cluster_data(hdr, current_cluster);
        if (!current_cluster_data) break;
        
        uint32_t available_in_cluster = g_cluster_size - current_offset;
        uint32_t bytes_to_copy = (bmp_size - bytes_read > available_in_cluster) ? 
                                available_in_cluster : (bmp_size - bytes_read);
        
        memcpy(bmp_data + bytes_read, (uint8_t *)current_cluster_data + current_offset, bytes_to_copy);
        bytes_read += bytes_to_copy;
        
        // Move to next cluster
        current_cluster++;
        current_offset = 0; // Start from beginning of next cluster
        
        // Check if we've read enough or reached end of data area
        if (current_cluster >= g_total_clusters + 2) break;
    }
    
    // Verify we read the complete file
    if (bytes_read >= bmp_size) {
        // Try to extract filename from BMP metadata
        char extracted_name[256] = {0};
        try_extract_filename_from_bmp(bmp_data, bmp_size, extracted_name);
        
        // Calculate SHA1
        char sha1_str[41];
        calculate_sha1(bmp_data, bmp_size, sha1_str);
        
        // Generate filename based on available information
        char filename[256];
        if (strlen(extracted_name) > 0) {
            snprintf(filename, sizeof(filename), "%s", extracted_name);
        } else {
            snprintf(filename, sizeof(filename), "recovered_cluster_%u_offset_%u.bmp", 
                    cluster_num, offset_in_cluster);
        }
        
        // Create output directory
        mkdir("recovered_bmps", 0755);
        
        // Generate output file path
        char output_path[512];
        snprintf(output_path, sizeof(output_path), "recovered_bmps/%s_%s", 
                sha1_str, filename);
        
        // Write the recovered BMP file
        FILE *outfile = fopen(output_path, "wb");
        if (outfile) {
            fwrite(bmp_data, 1, bmp_size, outfile);
            fclose(outfile);
            
            printf("%s  %s\n", sha1_str, filename);
            fflush(stdout);
        } else {
            printf("Failed to write recovered file: %s\n", output_path);
        }
        
        free(bmp_data);
        return 1; // Successfully extracted
    }
    
    free(bmp_data);
    return 0;
}

// Scan all data clusters for BMP file signatures
void recover_bmps(struct fat32hdr *hdr) {
    printf("Scanning for BMP files in formatted filesystem...\n");
    
    uint32_t recovered_count = 0;
    
    // Scan all data clusters
    for (uint32_t cluster = 2; cluster < g_total_clusters + 2; cluster++) {
        void *cluster_data = get_cluster_data(hdr, cluster);
        if (!cluster_data) continue;
        
        uint8_t *data = (uint8_t *)cluster_data;
        
        // Scan through the cluster looking for BMP signatures
        for (uint32_t offset = 0; offset < g_cluster_size - 1; offset++) {
            // Look for BMP signature "BM"
            if (data[offset] == 'B' && data[offset + 1] == 'M') {
                // Try to extract BMP starting from this position
                if (extract_bmp_from_cluster(hdr, cluster, offset)) {
                    recovered_count++;
                    // Skip ahead to avoid finding overlapping BMPs
                    offset += 54; // Skip BMP header
                }
            }
        }
    }
}

// Try to extract filename from BMP metadata or other sources
void try_extract_filename_from_bmp(uint8_t *bmp_data, uint32_t bmp_size, char *extracted_name) {
    extracted_name[0] = '\0';
    
    // BMP files don't typically contain filename metadata in the header
    // But we can look for common patterns or embedded strings
    
    // Look for strings that might be filenames in the first 1KB of the file
    uint32_t search_limit = (bmp_size > 1024) ? 1024 : bmp_size;
    
    for (uint32_t i = 54; i < search_limit - 8; i++) {
        // Look for potential filename patterns (ASCII strings ending in .bmp)
        if (bmp_data[i] >= 32 && bmp_data[i] <= 126) { // Printable ASCII
            char temp_str[256] = {0};
            int str_len = 0;
            
            // Extract potential string
            for (uint32_t j = i; j < search_limit && str_len < 255; j++) {
                if (bmp_data[j] >= 32 && bmp_data[j] <= 126) {
                    temp_str[str_len++] = bmp_data[j];
                } else {
                    break;
                }
            }
            
            // Check if it looks like a filename
            if (str_len >= 8 && str_len <= 100) {
                char *dot = strrchr(temp_str, '.');
                if (dot && strcasecmp(dot, ".bmp") == 0) {
                    // Found potential filename
                    strncpy(extracted_name, temp_str, 255);
                    extracted_name[255] = '\0';
                    return;
                }
            }
        }
    }
}

// Scan for deleted directory entries to recover original filenames
void scan_for_deleted_entries(struct fat32hdr *hdr) {
    printf("Searching for deleted directory entries...\n");
    
    // Scan root directory and subdirectories for deleted entries
    scan_deleted_in_cluster(hdr, hdr->BPB_RootClus);
    
    // Also scan some random clusters that might contain old directory data
    for (uint32_t cluster = 2; cluster < g_total_clusters + 2; cluster += 10) {
        scan_deleted_in_cluster(hdr, cluster);
    }
}

// Helper function to scan a specific cluster for deleted entries
void scan_deleted_in_cluster(struct fat32hdr *hdr, uint32_t cluster_num) {
    if (cluster_num < 2) return;
    
    void *cluster_data = get_cluster_data(hdr, cluster_num);
    if (!cluster_data) return;
    
    struct fat32dent *entries = (struct fat32dent *)cluster_data;
    
    for (uint32_t i = 0; i < g_entries_per_cluster; i++) {
        struct fat32dent *entry = &entries[i];
        
        // Look for deleted entries (first byte is 0xE5)
        if (entry->DIR_Name[0] == 0xE5) {
            // Skip long file name entries
            if ((entry->DIR_Attr & 0x0F) == 0x0F) continue;
            
            // Skip directories
            if (entry->DIR_Attr & ATTR_DIRECTORY) continue;
            
            // Check if it might be a BMP file
            char filename[256];
            fat32_name_to_string(entry->DIR_Name, filename);
            
            if (is_bmp_file(filename)) {
                // Try to recover this deleted BMP file
                uint32_t start_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
                uint32_t file_size = entry->DIR_FileSize;
                
                if (start_cluster >= 2 && file_size > 0) {
                    // Restore first character of filename (commonly lost)
                    entry->DIR_Name[0] = '?'; // Replace with placeholder
                    fat32_name_to_string(entry->DIR_Name, filename);
                    
                    printf("Found deleted BMP: %s (cluster %u, size %u)\n", 
                           filename, start_cluster, file_size);
                    
                    // Try to extract the file
                    extract_deleted_bmp_file(hdr, entry, filename);
                }
            }
        }
    }
}

// Extract a deleted BMP file
void extract_deleted_bmp_file(struct fat32hdr *hdr, struct fat32dent *entry, const char *filename) {
    uint32_t file_size = entry->DIR_FileSize;
    uint32_t start_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
    
    if (file_size == 0 || start_cluster < 2) {
        return;
    }
    
    // Store file data in memory
    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        printf("Memory allocation failed for deleted file extraction\n");
        return;
    }
    
    // Read data sequentially (FAT chain might be corrupted)
    uint32_t bytes_read = 0;
    uint32_t current_cluster = start_cluster;
    
    while (bytes_read < file_size && current_cluster >= 2 && current_cluster < g_total_clusters + 2) {
        void *cluster_data = get_cluster_data(hdr, current_cluster);
        if (!cluster_data) break;
        
        uint32_t bytes_to_copy = (file_size - bytes_read > g_cluster_size) ? 
                                g_cluster_size : (file_size - bytes_read);
        
        memcpy(file_data + bytes_read, cluster_data, bytes_to_copy);
        bytes_read += bytes_to_copy;
        
        // Try to follow FAT chain, but if it's broken, try sequential clusters
        uint32_t next_cluster = get_next_cluster(g_fat_table, current_cluster);
        if (next_cluster >= 2 && next_cluster < g_total_clusters + 2) {
            current_cluster = next_cluster;
        } else {
            current_cluster++; // Try next sequential cluster
        }
    }
    
    // Verify BMP header
    if (bytes_read >= 14 && file_data[0] == 'B' && file_data[1] == 'M') {
        // Calculate SHA1
        char sha1_str[41];
        calculate_sha1(file_data, bytes_read, sha1_str);
        
        // Create output directory
        mkdir("recovered_bmps", 0755);
        
        // Generate output file path
        char output_path[512];
        snprintf(output_path, sizeof(output_path), "recovered_bmps/%s_deleted_%s", 
                sha1_str, filename);
        
        // Write the recovered BMP file
        FILE *outfile = fopen(output_path, "wb");
        if (outfile) {
            fwrite(file_data, 1, bytes_read, outfile);
            fclose(outfile);
            
            printf("%s  deleted_%s\n", sha1_str, filename);
            fflush(stdout);
        } else {
            printf("Failed to write recovered deleted file: %s\n", output_path);
        }
    }
    
    free(file_data);
}