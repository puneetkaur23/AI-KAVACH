/*
 * targets/demo_packet_parser/vuln.c
 * Deliberately vulnerable test target for AI Kavach CRS.
 * 
 * Simulates a network packet / binary file parser.
 * Vulnerability: CWE-787 (Out-of-bounds Write / Heap Buffer Overflow)
 * Description: Header declares a packet length, but copies into a fixed-size buffer
 *              without validating that length <= MAX_PAYLOAD_SIZE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PAYLOAD 64

typedef struct {
    uint16_t magic;      /* 0x4B56 ("KV") */
    uint16_t length;     /* Payload length */
    uint8_t  type;       /* Message type */
} PacketHeader;

void process_packet_payload(const uint8_t *data, size_t len) {
    char local_buf[MAX_PAYLOAD];
    
    /* VULNERABILITY (CWE-787):
     * Copies 'len' bytes into 64-byte local_buf without verifying len <= sizeof(local_buf)
     */
    memcpy(local_buf, data, len);
    
    printf("[+] Packet payload processed successfully (len=%zu)\n", len);
}

int parse_packet_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "[-] Failed to open file: %s\n", filename);
        return 1;
    }

    PacketHeader hdr;
    if (fread(&hdr, sizeof(PacketHeader), 1, fp) != 1) {
        fclose(fp);
        return 1;
    }

    /* Check magic byte */
    if (hdr.magic != 0x4B56) {
        /* Not a valid KV packet, treat whole file as raw payload */
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        
        if (size <= 0 || size > 2048) {
            fclose(fp);
            return 1;
        }

        uint8_t *raw_data = (uint8_t *)malloc(size);
        if (!raw_data) {
            fclose(fp);
            return 1;
        }

        fread(raw_data, 1, size, fp);
        fclose(fp);

        process_packet_payload(raw_data, size);
        free(raw_data);
        return 0;
    }

    uint8_t *payload = (uint8_t *)malloc(hdr.length);
    if (!payload) {
        fclose(fp);
        return 1;
    }

    size_t bytes_read = fread(payload, 1, hdr.length, fp);
    fclose(fp);

    if (bytes_read > 0) {
        process_packet_payload(payload, bytes_read);
    }

    free(payload);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_packet_file>\n", argv[0]);
        return 1;
    }

    return parse_packet_file(argv[1]);
}
