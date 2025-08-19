/**
 * @file check.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Simple error checking utility
 */

#ifndef __CHECK_HPP__
#define __CHECK_HPP__

#include <cstdint>
#include <cstdio>
#include <cstdlib>

#ifdef PRINT
#   define print(a) a
#else
#   define print(a) 
#endif

static void sys_error(const char * msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

#define STRINGIFY(x) #x
#define STR(x) STRINGIFY(x)

#define PCHECK(ret)                                                            \
do {                                                                           \
    if ((ret) == -1) { sys_error(__FILE__ ":" STR(__LINE__) " " #ret); }       \
} while (0)

#define CHECK(ret)                                                             \
do {                                                                           \
    if (!(ret)) { sys_error(__FILE__ ":" STR(__LINE__) " " #ret); }            \
} while (0)

#define ERROR(str)                                                             \
do {                                                                           \
    fprintf(stderr, __FILE__ ":" STR(__LINE__) " " str); exit(EXIT_FAILURE);   \
} while (0)

static uint32_t hash32(const uint8_t * content, uint32_t size) // Inspired from djb2
{
    uint32_t hash = 5381; // Large prime number

    for(uint32_t i = 0; i < size; ++i)
        hash = ((hash << 5) + hash) + content[i];

    return hash;
}

#endif
