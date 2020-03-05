#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../basic04-pinning-maps/common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

static const char *__doc__ = "XDP stats program\n"
	" - Finding xdp_stats_map via --dev name info\n";

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},
	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }}
};


#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}



// /* BPF_MAP_TYPE_ARRAY */
// void map_get_value_array(int fd, __u32 key, int *value)
// {
// 	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
// 		fprintf(stderr,
// 			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
// 	}
// }

// static bool map_collect(int fd, __u32 map_type, __u32 key, int *rec)
// {
// 	int* value;

//     map_get_value_array(fd, key, &value);


//     *rec = *value;
// 	return true;
// }


// static void stats_collect(int map_fd,
// 			  int  *info)
// {
// 	/* Collect all XDP actions stats  */
// 	__u32 key;

// 	for (key = 0; key < XDP_ACTION_MAX; key++) {
// 		map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
// 	}
// }


char* prints[] = {  "Passed the ethhdr (1 if true):",
                    "Passed the ip6hdr (58 if yes):",
                    "IPPROTO_ICMPV6 should be 58:",
                    "Passed the icmpv6 (not -1):",
                    "Icmp sequence val:",
                    "limit: ",
                    "ntohs sequence val:",
                    "htons sequence val:",
                    "struct sequence val:",
                    "struct u16 data val1:",
                    "struct u16 data val2:",
                    "ntohs struct sequence:",
                    "ntohs struct seq modulus:",
                    "icmp identifier:",
                    "icmp checksum"
                    };

static int stats_poll(int fd, __u32 map_id, int interval, char* ifname)
{

    int i;
    int* res;
    /* Trick to pretty printf with thousands separators use %' */
    setlocale(LC_NUMERIC, "en_US");

    while (1) {

        // for(i = 0; i < 5; i++)
        // {

        printf(  "--------------------------------\n");
        for(i=0; i<5; i++)
        {
            if ((bpf_map_lookup_elem(fd, &i, res)) != 0) {
                fprintf(stderr,"ERR: bpf_map_lookup_elem failed key:0x%X\n", i);
            } else{

                printf("%d-", i);
                switch (i){
                    case 4:
                        printf("%s %d %s %d\n", prints[i], res[0], prints[i+1],(unsigned)16636);
                        break;
                    default:
                        printf("%s %d\n",prints[i], res[0]);
                        break;
                }
            }
        }
        for(i=5;i<14; i++)
        {
            if ((bpf_map_lookup_elem(fd, &i, res)) != 0) {
                fprintf(stderr,"ERR: bpf_map_lookup_elem failed key:0x%X\n", i);
            } else{

                printf("%d-", i);
                printf("%s %d\n", prints[i+1],res[0]);
            }
        }
        printf("Sizeof int %d and of short %d and unsigned short %d\n",sizeof(int),sizeof(short),sizeof(unsigned short));
        printf("\n");
        // }
        sleep(interval);
	}

    return EXIT_OK;
}


#ifndef PATH_MAX
#define PATH_MAX	4096
#endif
const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info info = { 0 };
	char pin_dir[PATH_MAX];
	int stats_map_fd;
	int interval = 2;
	int len, err;

	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	stats_map_fd = open_bpf_map_file(pin_dir, "xdp_dbg_map", &info);
	if (stats_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

    /* check map info, e.g. datarec is expected size */
    map_expect.key_size    = sizeof(__u32);
    map_expect.value_size  = sizeof(int);
    map_expect.max_entries = 15;
    err = check_map_fd_info(&info, &map_expect);
    if (err) {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        return err;
    }

    if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}

    stats_poll(stats_map_fd,info.id,interval,cfg.ifname);
}