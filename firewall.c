#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s [[-]port]\n", argv[0]);
        return 1;
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/ports");
    if (map_fd < 0) {
        printf("Couldn't find ports map\n");
        return 1;
    }

    int port = atoi(argv[1]);
    if (port > 65535 || port < -65535) {
        printf("Invalid port: %d\n", port);
        return 1;
    } else if (port < 0) {
        port *= -1;
        int ret = bpf_map_delete_elem(map_fd, &port);
        if (ret != 0) {
            printf("Error removing port: %d\n", port);
            return 1;
        }
        printf("Removed port: %d\n", port);
    } else {
        __u8 value = 1;
        int ret = bpf_map_update_elem(map_fd, &port, &value, BPF_ANY);
        if (ret != 0) {
            printf("Error adding port: %d\n", port);
            return 1;
        }
        printf("Added port: %d\n", port);
    }

    return 0;
}
