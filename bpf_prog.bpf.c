#include <linux/bpf.h>
#include "bpf_helpers.h"

int hello_world() {
        bpf_printk("Hello World\n");
        return SK_PASS;
}
