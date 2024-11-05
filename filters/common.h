#include <linux/if_ether.h>


const __u16 mark = 0xCFAE;

struct custom_header{
    struct ethhdr eth;
    struct {
        __u16 sequence;
        __u16 protocol;
    } data;
};
