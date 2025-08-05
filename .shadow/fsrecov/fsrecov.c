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

// Check if data contains a valid BMP header
int is_valid_bmp_header(const uint8_t *data, uint32_t cluster_size) {
    // Check BMP signature
    if (data[0] != 'B' || data[1] != 'M') {
        return 0;
    }
    
    // Check if we have enough data for the header
    if (cluster_size < 54) {  // Minimum BMP header size
        return 0;
    }
    
    // Extract file size from BMP header (bytes 2-5)
    uint32_t file_size = *(uint32_t*)(data + 2);
    
    // Basic sanity checks
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
    
    // Allocate memory for the file
    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        printf("Memory allocation failed for carved file\n");
        return;
    }
    
    // Read clusters sequentially (we don't have FAT chain info)
    uint32_t bytes_read = 0;
    uint32_t current_cluster = start_cluster;
    
    while (bytes_read < file_size && current_cluster < g_total_clusters + 2) {
        void *cluster_data = get_cluster_data(hdr, current_cluster);
        if (!cluster_data) break;
        
        uint32_t bytes_to_copy = (file_size - bytes_read > g_cluster_size) ? 
                                g_cluster_size : (file_size - bytes_read);
        
        memcpy(file_data + bytes_read, cluster_data, bytes_to_copy);
        bytes_read += bytes_to_copy;
        current_cluster++;  // Move to next sequential cluster
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

// File carving: scan all clusters for BMP signatures
void carve_bmp_files(struct fat32hdr *hdr) {
    printf("Scanning %u clusters for BMP file signatures...\n", g_total_clusters);
    
    uint32_t found_count = 0;
    
    // Scan all data clusters
    for (uint32_t cluster = 2; cluster < g_total_clusters + 2; cluster++) {
        void *cluster_data = get_cluster_data(hdr, cluster);
        if (!cluster_data) continue;
        
        uint8_t *data = (uint8_t *)cluster_data;
        
        // Check if this cluster starts with a BMP signature
        if (is_valid_bmp_header(data, g_cluster_size)) {
            // Extract file size from BMP header
            uint32_t file_size = *(uint32_t*)(data + 2);
            
            printf("Found BMP signature at cluster %u, file size: %u bytes\n", 
                   cluster, file_size);
            
            extract_carved_bmp(hdr, cluster, file_size);
            found_count++;
        }
        
        // Also check for BMP signatures at other offsets within the cluster
        // (in case a BMP file doesn't start at cluster boundary)
        for (uint32_t offset = 1; offset < g_cluster_size - 54; offset++) {
            if (data[offset] == 'B' && data[offset + 1] == 'M') {
                if (is_valid_bmp_header(data + offset, g_cluster_size - offset)) {
                    uint32_t file_size = *(uint32_t*)(data + offset + 2);
                    
                    printf("Found BMP signature at cluster %u offset %u, file size: %u bytes\n", 
                           cluster, offset, file_size);
                    
                    // For non-aligned BMPs, we'd need more complex extraction
                    // For now, just report them
                    found_count++;
                }
            }
        }
        
        // Progress indicator for large filesystems
        if (cluster % 1000 == 0) {
            printf("Scanned %u/%u clusters...\r", cluster - 2, g_total_clusters);
            fflush(stdout);
        }
    }
    
    printf("\nFile carving completed. Found %u potential BMP files.\n", found_count);
}