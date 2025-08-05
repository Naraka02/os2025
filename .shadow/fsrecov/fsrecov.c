#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "fat32.h"

void *map_disk(const char *fname);
void print_fat32_info(struct fat32hdr *hdr);
uint32_t *get_fat_table(struct fat32hdr *hdr);
void *get_cluster_data(struct fat32hdr *hdr, uint32_t cluster_num);
uint32_t get_next_cluster(uint32_t *fat_table, uint32_t cluster_num);
void scan_clusters(struct fat32hdr *hdr);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s fs-image\n", argv[0]);
        exit(1);
    }

    setbuf(stdout, NULL);

    assert(sizeof(struct fat32hdr) == 512); // defensive

    // map disk image to memory
    struct fat32hdr *hdr = map_disk(argv[1]);

    // Print FAT32 filesystem information
    print_fat32_info(hdr);

    // Scan clusters
    scan_clusters(hdr);

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
    
    // Calculated values
    uint32_t bytes_per_cluster = hdr->BPB_BytsPerSec * hdr->BPB_SecPerClus;
    uint32_t total_clusters = (hdr->BPB_TotSec32 - hdr->BPB_RsvdSecCnt - 
                              (hdr->BPB_NumFATs * hdr->BPB_FATSz32)) / hdr->BPB_SecPerClus;
    uint32_t fat_start_sector = hdr->BPB_RsvdSecCnt;
    uint32_t data_start_sector = hdr->BPB_RsvdSecCnt + (hdr->BPB_NumFATs * hdr->BPB_FATSz32);
    
    printf("\n=== Calculated Information ===\n");
    printf("Bytes per Cluster: %u\n", bytes_per_cluster);
    printf("Total Clusters: %u\n", total_clusters);
    printf("FAT Start Sector: %u\n", fat_start_sector);
    printf("Data Start Sector: %u\n", data_start_sector);
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
    uint32_t data_start_sector = hdr->BPB_RsvdSecCnt + (hdr->BPB_NumFATs * hdr->BPB_FATSz32);
    uint32_t cluster_size = hdr->BPB_BytsPerSec * hdr->BPB_SecPerClus;
    
    uint32_t cluster_offset = data_start_sector * hdr->BPB_BytsPerSec + 
                              (cluster_num - 2) * cluster_size;
    
    return disk + cluster_offset;
}

uint32_t get_next_cluster(uint32_t *fat_table, uint32_t cluster_num) {
    uint32_t next_cluster = fat_table[cluster_num] & 0x0FFFFFFF;
    
    if (next_cluster >= 0x0FFFFFF8) {
        return 0;
    }
    
    return next_cluster;
}

void scan_clusters(struct fat32hdr *hdr) {
    printf("=== Cluster Scan ===\n");
    
    uint32_t *fat_table = get_fat_table(hdr);
    uint32_t total_clusters = (hdr->BPB_TotSec32 - hdr->BPB_RsvdSecCnt - 
                              (hdr->BPB_NumFATs * hdr->BPB_FATSz32)) / hdr->BPB_SecPerClus;
    
    uint32_t free_clusters = 0;
    uint32_t used_clusters = 0;
    uint32_t bad_clusters = 0;
    
    printf("Scanning %u clusters...\n", total_clusters);
    
    for (uint32_t i = 2; i < total_clusters + 2; i++) {
        uint32_t fat_entry = fat_table[i] & 0x0FFFFFFF;
        
        if (fat_entry == 0) {
            free_clusters++;
        } else if (fat_entry == 0x0FFFFFF7) {
            bad_clusters++;
            printf("Bad cluster found: %u\n", i);
        } else if (fat_entry >= 0x0FFFFFF8) {
            used_clusters++;
        } else {
            used_clusters++;
        }
        
        if (i < 10 || i > total_clusters + 2 - 5) {
            printf("Cluster %u: FAT entry = 0x%08X", i, fat_entry);
            if (fat_entry == 0) {
                printf(" (FREE)");
            } else if (fat_entry == 0x0FFFFFF7) {
                printf(" (BAD)");
            } else if (fat_entry >= 0x0FFFFFF8) {
                printf(" (EOF)");
            } else {
                printf(" (-> %u)", fat_entry);
            }
            printf("\n");
        }
    }
    
    printf("\nCluster Statistics:\n");
    printf("Total clusters: %u\n", total_clusters);
    printf("Free clusters: %u (%.2f%%)\n", free_clusters, 
           (double)free_clusters / total_clusters * 100);
    printf("Used clusters: %u (%.2f%%)\n", used_clusters,
           (double)used_clusters / total_clusters * 100);
    printf("Bad clusters: %u\n", bad_clusters);
    
    printf("\nRoot directory cluster chain:\n");
    uint32_t current_cluster = hdr->BPB_RootClus;
    int chain_length = 0;
    
    while (current_cluster != 0 && current_cluster >= 2 && chain_length < 10) {
        printf("Cluster %u", current_cluster);
        
        uint32_t next = get_next_cluster(fat_table, current_cluster);
        if (next == 0) {
            printf(" (EOF)\n");
        } else {
            printf(" -> ");
        }
        
        current_cluster = next;
        chain_length++;
    }
    
    if (chain_length >= 10) {
        printf("... (chain continues)\n");
    }
    
    printf("\n");
}
