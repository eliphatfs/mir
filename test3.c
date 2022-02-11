#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "mir.h"
#include "mir-gen.h"

void * ptr;
typedef void (*func_t)();

void run(int opt_lv) {
    void* ctx = MIR_init();
    MIR_gen_init(ctx, 1);
    MIR_gen_set_optimize_level(ctx, 0, opt_lv);
    /* MIR_gen_set_debug_file(ctx, 0, fopen("test3.log", "w")); */

    void* module = MIR_new_module(ctx, "test");
    MIR_item_t func = MIR_new_func(ctx, "tester", 0, NULL, 0);
    MIR_append_insn(ctx, func, MIR_new_insn(
        ctx, MIR_MOV,
        MIR_new_mem_op(ctx, MIR_T_I64, (intptr_t)ptr, 0, 0, 1),
        MIR_new_int_op(ctx, 12345)
    ));
    MIR_finish_func(ctx);
    MIR_finish_module(ctx);

    MIR_load_module(ctx, module);

    MIR_link(ctx, MIR_set_gen_interface, NULL);

    printf("before running level %d\n", opt_lv);
    ((func_t)(func->addr))();
    printf("after running level %d\n", opt_lv);

    MIR_gen_finish(ctx);
    MIR_finish(ctx);
}

int main() {
    // 64-bit machine
    if (sizeof(void*) == 8) {
        int fd = open("./test-high-mov.tmp", O_RDWR | O_APPEND | O_CREAT, 0666);
        write(fd, "garbbarish", 10); lseek(fd, 0, SEEK_SET);
        if (fd == -1) printf("Create file failed\n");
        ptr = mmap(0xdeadbe0000, 8, PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, 0);
        if (ptr == -1) printf("Mmap failed - %d\n", errno);
        printf("%p\n", ptr);
        *(long long*)ptr = 54321;
        printf("%lld\n", *(long long*)ptr);
        run(0);  // Works
        printf("%lld\n", *(long long*)ptr);
        run(1);  // Fails
        run(2); run(3);  // Also fails
    }
    else {
        printf("not 64-bit machine\n");
    }
    return 0;
}
