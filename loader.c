
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t running = 1;

static void stop(int sig)
{
    running = 0;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <interface> [port]\n", argv[0]);
        return 1;
    }

    char *end;
    unsigned long port = argc == 3
        ? strtoul(argv[2], &end, 10) : 4040;

    if (port < 1 || port > 65535 ||
        (argc == 3 && (*argv[2] == '\0' || *end != '\0'))) {
        fprintf(stderr, "Invalid port\n");
        return 1;
    }

    unsigned int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface: %s\n", argv[1]);
        return 1;
    }

    struct bpf_object *obj =
        bpf_object__open_file("drop.bpf.o", NULL);

    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Could not open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Could not load BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "drop_tcp");
    struct bpf_map *map =
        bpf_object__find_map_by_name(obj, "blocked_port");

    if (!prog || !map) {
        fprintf(stderr, "Program or map not found\n");
        bpf_object__close(obj);
        return 1;
    }

    unsigned int key = 0;
    unsigned int value = (unsigned int)port;

    if (bpf_map_update_elem(bpf_map__fd(map),
                            &key, &value, BPF_ANY)) {
        perror("Map update failed");
        bpf_object__close(obj);
        return 1;
    }

    __u32 flags = XDP_FLAGS_SKB_MODE |
                  XDP_FLAGS_UPDATE_IF_NOEXIST;

    if (bpf_xdp_attach(ifindex, bpf_program__fd(prog),
                       flags, NULL)) {
        fprintf(stderr, "XDP attach failed\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("Blocking incoming IPv4 TCP port %lu on %s\n",
           port, argv[1]);
    printf("Press Ctrl+C to stop.\n");

    signal(SIGINT, stop);
    signal(SIGTERM, stop);

    while (running)
        pause();

    if (bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL))
        fprintf(stderr, "Warning: detach failed\n");

    bpf_object__close(obj);
    return 0;
}
