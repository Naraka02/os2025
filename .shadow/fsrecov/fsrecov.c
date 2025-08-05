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
void carve_bmp_files(struct fat32hdr *hdr);
int is_valid_bmp_header(const uint8_t *data, uint32_t cluster_size);
void extract_carved_bmp(struct fat32hdr *hdr, uint32_t start_cluster, uint32_t file_size);
void carve_directory_info(struct fat32hdr *hdr);
void extract_lfn_from_cluster(void *cluster_data, uint32_t cluster_num);
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
    printf("=== Directory Information Recovery ===\n");
    carve_directory_info(hdr);
    
    printf("\n=== BMP File Carving ===\n");
    carve_bmp_files(hdr);

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

int is_valid_bmp_header(const uint8_t *data, uint32_t cluster_size) {
    // Check BMP signature
    if (data[0] != 'B' || data[1] != 'M') {
        return 0;
    }
    
    if (cluster_size < 54) {  // Minimum BMP header size
        return 0;
    }
    
    // Extract file size from BMP header (bytes 2-5)
    uint32_t file_size = *(uint32_t*)(data + 2);
    
    if (file_size < 54 || file_size > 100 * 1024 * 1024) {  // Between 54 bytes and 100MB
        return 0;
    }
    
    // Extract data offset (bytes 10-13)
    uint32_t data_offset = *(uint32_t*)(data + 10);
    if (data_offset < 54 || data_offset > file_size) {
        return 0;
    }
    
    // Extract header size (bytes 14-17)
    uint32_t header_size = *(uint32_t*)(data + 14);
    if (header_size < 40) {  // Minimum DIB header size
        return 0;
    }
    
    // Extract width and height (bytes 18-21 and 22-25)
    int32_t width = *(int32_t*)(data + 18);
    int32_t height = *(int32_t*)(data + 22);
    
    if (width <= 0 || height == 0 || width > 10000 || abs(height) > 10000) {
        return 0;
    }
    
    return 1;
}

// Extract a carved BMP file
void extract_carved_bmp(struct fat32hdr *hdr, uint32_t start_cluster, uint32_t file_size) {
    static int carved_file_counter = 0;
    
    // Store file in memory
    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        printf("Memory allocation failed for carved file\n");
        return;
    }
    
    // Read clusters sequentially
    uint32_t bytes_read = 0;
    uint32_t current_cluster = start_cluster;
    
    while (bytes_read < file_size && current_cluster < g_total_clusters + 2) {
        void *cluster_data = get_cluster_data(hdr, current_cluster);
        if (!cluster_data) break;
        
        uint32_t bytes_to_copy = (file_size - bytes_read > g_cluster_size) ? 
                                g_cluster_size : (file_size - bytes_read);
        
        memcpy(file_data + bytes_read, cluster_data, bytes_to_copy);
        bytes_read += bytes_to_copy;
        current_cluster++;
    }
    
    // Verify we got the complete file
    if (bytes_read >= file_size && file_data[0] == 'B' && file_data[1] == 'M') {
        // Calculate SHA1 hash
        char sha1_str[41];
        calculate_sha1(file_data, file_size, sha1_str);
        
        // Generate filename based on cluster and counter
        char filename[256];
        snprintf(filename, sizeof(filename), "carved_cluster_%u_file_%d.bmp", 
                start_cluster, ++carved_file_counter);
        
        printf("%s  %s\n", sha1_str, filename);
        fflush(stdout);
        
        // Optionally save the file (uncomment if needed)
        /*
        mkdir("recovered_bmps", 0755);
        char output_path[512];
        snprintf(output_path, sizeof(output_path), "recovered_bmps/%s", filename);
        
        FILE *outfile = fopen(output_path, "wb");
        if (outfile) {
            fwrite(file_data, 1, file_size, outfile);
            fclose(outfile);
        }
        */
    }
    
    free(file_data);
}

void carve_bmp_files(struct fat32hdr *hdr) {
    // Scan all data clusters
    for (uint32_t cluster = 2; cluster < g_total_clusters + 2; cluster++) {
        void *cluster_data = get_cluster_data(hdr, cluster);
        if (!cluster_data) continue;
        
        uint8_t *data = (uint8_t *)cluster_data;
        
        // Check if this cluster starts with a BMP signature
        if (is_valid_bmp_header(data, g_cluster_size)) {
            uint32_t file_size = *(uint32_t*)(data + 2);
            extract_carved_bmp(hdr, cluster, file_size);
        }
    }

}

// Extract long filename from a single LFN entry
void extract_single_lfn(uint8_t *lfn_data, char *partial_name) {
    int char_count = 0;
    
    // Extract Unicode characters and convert to ASCII (simplified)
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

// Check if filename has BMP extension
int is_bmp_extension(const char *filename) {
    int len = strlen(filename);
    if (len < 4) return 0;
    
    const char *ext = filename + len - 4;
    return (strcasecmp(ext, ".bmp") == 0);
}

// Extract LFN entries from a directory cluster
void extract_lfn_from_cluster(void *cluster_data, uint32_t cluster_num) {
    struct fat32dent *entries = (struct fat32dent *)cluster_data;
    char current_long_filename[256] = "";
    
    for (uint32_t i = 0; i < g_entries_per_cluster; i++) {
        struct fat32dent *entry = &entries[i];
        uint8_t *entry_data = (uint8_t *)entry;
        
        // Skip empty entries
        if (entry->DIR_Name[0] == 0x00) break;
        
        // Check if this is an LFN entry
        if ((entry->DIR_Attr & 0x0F) == 0x0F) {
            uint8_t sequence = entry_data[0] & 0x1F;
            uint8_t is_last = (entry_data[0] & 0x40) ? 1 : 0;
            
            char partial_name[256];
            extract_single_lfn(entry_data, partial_name);
            
            // If this is the first LFN entry (highest sequence number), start fresh
            if (is_last) {
                strcpy(current_long_filename, partial_name);
            } else {
                // Prepend this fragment to build the complete name
                char temp[256];
                strcpy(temp, partial_name);
                strcat(temp, current_long_filename);
                strcpy(current_long_filename, temp);
            }
        }
        // Check for regular directory entries (including deleted ones)
        else if (entry->DIR_Name[0] != 0xE5 || entry->DIR_Name[0] == 0xE5) {
            char short_name[13];
            
            // Convert 8.3 filename
            int j = 0;
            for (int k = 0; k < 8 && entry->DIR_Name[k] != ' '; k++) {
                short_name[j++] = tolower(entry->DIR_Name[k]);
            }
            if (entry->DIR_Name[8] != ' ') {
                short_name[j++] = '.';
                for (int k = 8; k < 11 && entry->DIR_Name[k] != ' '; k++) {
                    short_name[j++] = tolower(entry->DIR_Name[k]);
                }
            }
            short_name[j] = '\0';
            
            uint32_t start_cluster = (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
            uint32_t file_size = entry->DIR_FileSize;
            
            // Determine which filename to use (long or short)
            const char *display_name = short_name;
            if (strlen(current_long_filename) > 0) {
                display_name = current_long_filename;
            }
            
            // Only show BMP files
            if (is_bmp_extension(display_name) || is_bmp_extension(short_name)) {
                // Try to extract and hash the BMP file if we have valid cluster info
                if (start_cluster >= 2 && file_size > 0) {
                    // Try to read the file data and calculate hash
                    uint8_t *file_data = malloc(file_size);
                    if (file_data) {
                        uint32_t bytes_read = 0;
                        uint32_t current_cluster = start_cluster;
                        
                        // Read clusters sequentially 
                        while (bytes_read < file_size && current_cluster >= 2 && current_cluster < g_total_clusters + 2) {
                            void *cluster_data = get_cluster_data(hdr, current_cluster);
                            if (!cluster_data) break;
                            
                            uint32_t bytes_to_copy = (file_size - bytes_read > g_cluster_size) ? 
                                                    g_cluster_size : (file_size - bytes_read);
                            
                            memcpy(file_data + bytes_read, cluster_data, bytes_to_copy);
                            bytes_read += bytes_to_copy;
                            current_cluster++;
                        }
                        
                        // If we got a complete file, calculate hash
                        if (bytes_read >= file_size && bytes_read >= 14 && 
                            file_data[0] == 'B' && file_data[1] == 'M') {
                            char sha1_str[41];
                            calculate_sha1(file_data, bytes_read, sha1_str);
                            printf("%s  %s\n", sha1_str, display_name);
                        }
                        
                        free(file_data);
                    }
                } else {
                    // For deleted files or files without valid cluster info, just show filename
                    printf("(no_hash)  %s\n", display_name);
                }
            }
            
            // Reset long filename after processing the directory entry
            current_long_filename[0] = '\0';
        }
    }
}

// Carve directory information from all clusters
void carve_directory_info(struct fat32hdr *hdr) {
    printf("Scanning all clusters for BMP filenames...\n");
    
    for (uint32_t cluster = 2; cluster < g_total_clusters + 2; cluster++) {
        void *cluster_data = get_cluster_data(hdr, cluster);
        if (!cluster_data) continue;
        
        struct fat32dent *entries = (struct fat32dent *)cluster_data;
        
        // Check if this looks like a directory cluster
        int has_directory_entries = 0;
        
        for (uint32_t i = 0; i < g_entries_per_cluster && i < 4; i++) {
            struct fat32dent *entry = &entries[i];
            
            // Skip empty entries
            if (entry->DIR_Name[0] == 0x00) break;
            
            // Check for LFN entries or valid directory entries
            if ((entry->DIR_Attr & 0x0F) == 0x0F ||  // LFN entry
                entry->DIR_Name[0] == '.' ||           // . or .. entry
                (entry->DIR_Name[0] != 0xE5 && 
                 (entry->DIR_Attr & (ATTR_DIRECTORY | ATTR_ARCHIVE)))) {
                has_directory_entries = 1;
                break;
            }
            
            // Also check deleted entries
            if (entry->DIR_Name[0] == 0xE5 && 
                (entry->DIR_Attr & (ATTR_DIRECTORY | ATTR_ARCHIVE))) {
                has_directory_entries = 1;
                break;
            }
        }
        
        if (has_directory_entries) {
            extract_lfn_from_cluster(cluster_data, cluster);
        }
    }
    
    printf("BMP filename recovery completed.\n");
}