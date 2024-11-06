#include <linux/if_ether.h>


const __u16 mark = 0xCFAE;

struct custom_header{
    struct ethhdr eth;
    struct {
        __u16 sequence;
        __u16 protocol;
    } data;
};


#ifdef _DEBUG
#define log(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log(fmt, ...) do {} while (0)
#endif
