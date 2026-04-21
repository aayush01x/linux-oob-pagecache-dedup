#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

int create_and_queue(const char *filename, char **blocks, int num_blocks, long page_size);

#endif