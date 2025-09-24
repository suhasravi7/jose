/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2025 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <jose/jose.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/* Global tracking structure for custom allocator tests */
static struct {
    size_t malloc_calls;
    size_t realloc_calls;
    size_t free_calls;
    size_t total_allocated;
    size_t total_freed;
    int fail_malloc;
    int fail_realloc;
} alloc_stats = {0};

/* Custom allocator functions for testing */
static void*
test_malloc(size_t size)
{
    alloc_stats.malloc_calls++;
    
    if (alloc_stats.fail_malloc)
        return NULL;
    
    void *ptr = malloc(size);
    if (ptr) {
        alloc_stats.total_allocated += size;
    }
    return ptr;
}

static void*
test_realloc(void *ptr, size_t size)
{
    alloc_stats.realloc_calls++;
    
    if (alloc_stats.fail_realloc)
        return NULL;
    
    return realloc(ptr, size);
}

static void
test_free(void *ptr)
{
    alloc_stats.free_calls++;
    
    if (ptr) {
        free(ptr);
    }
}

static void
reset_alloc_stats(void)
{
    memset(&alloc_stats, 0, sizeof(alloc_stats));
}

/* Test basic allocator set/get functionality */
static void
test_allocator_set_get(void)
{
    printf("Testing jose_cfg_set_alloc and jose_cfg_get_alloc...\n");
    
    jose_cfg_auto_t *cfg = jose_cfg();
    assert(cfg != NULL);
    
    jose_malloc_t malloc_func = NULL;
    jose_realloc_t realloc_func = NULL;
    jose_free_t free_func = NULL;
    
    /* Test getting default allocators (should be NULL) */
    jose_cfg_get_alloc(cfg, &malloc_func, &realloc_func, &free_func);
    assert(malloc_func == NULL);
    assert(realloc_func == NULL);
    assert(free_func == NULL);
    
    /* Test setting custom allocators */
    int ret = jose_cfg_set_alloc(cfg, test_malloc, test_realloc, test_free);
    assert(ret == 0);
    
    /* Test getting custom allocators */
    jose_cfg_get_alloc(cfg, &malloc_func, &realloc_func, &free_func);
    assert(malloc_func == test_malloc);
    assert(realloc_func == test_realloc);
    assert(free_func == test_free);
    
    /* Test partial get (only some parameters) */
    malloc_func = NULL;
    jose_cfg_get_alloc(cfg, &malloc_func, NULL, NULL);
    assert(malloc_func == test_malloc);
    
    /* Test error handling - NULL cfg */
    ret = jose_cfg_set_alloc(NULL, test_malloc, test_realloc, test_free);
    assert(ret == EINVAL);
    
    printf("jose_cfg_set_alloc and jose_cfg_get_alloc tests passed!\n");
}

/* Test custom allocators with IO operations */
static void
test_allocator_io_operations(void)
{
    printf("Testing custom allocators with jose_io_malloc...\n");
    
    jose_cfg_auto_t *cfg = jose_cfg();
    assert(cfg != NULL);
    
    /* Set custom allocators */
    int ret = jose_cfg_set_alloc(cfg, test_malloc, test_realloc, test_free);
    assert(ret == 0);
    
    reset_alloc_stats();
    
    void *buf = NULL;
    size_t len = 0;
    
    /* Create IO object - should use custom malloc */
    jose_io_t *io = jose_io_malloc(cfg, &buf, &len);
    assert(io != NULL);
    assert(alloc_stats.malloc_calls > 0);
    
    /* Write some data - should trigger realloc */
    const char *test_data = "Hello, world! This is test data for the custom allocator.";
    size_t data_len = strlen(test_data);
    
    assert(io->feed(io, test_data, data_len));
    assert(alloc_stats.realloc_calls > 0);
    
    /* Close the IO object */
    assert(io->done(io));
    
    /* Verify data was written */
    assert(buf != NULL);
    assert(len == data_len);
    assert(memcmp(buf, test_data, data_len) == 0);
    
    /* Clean up - should trigger custom free */
    size_t initial_free_calls = alloc_stats.free_calls;
    jose_io_decref(io);
    assert(alloc_stats.free_calls > initial_free_calls);
    
    printf("Custom allocator IO operations tests passed!\n");
    printf("  malloc calls: %zu\n", alloc_stats.malloc_calls);
    printf("  realloc calls: %zu\n", alloc_stats.realloc_calls);
    printf("  free calls: %zu\n", alloc_stats.free_calls);
}

/* Test allocator failure scenarios */
static void
test_allocator_failures(void)
{
    printf("Testing allocator failure scenarios...\n");
    
    jose_cfg_auto_t *cfg = jose_cfg();
    assert(cfg != NULL);
    
    /* Set custom allocators */
    int ret = jose_cfg_set_alloc(cfg, test_malloc, test_realloc, test_free);
    assert(ret == 0);
    
    reset_alloc_stats();
    
    /* Test malloc failure */
    alloc_stats.fail_malloc = 1;
    
    void *buf = NULL;
    size_t len = 0;
    
    jose_io_t *io = jose_io_malloc(cfg, &buf, &len);
    /* IO creation should fail when malloc fails */
    assert(io == NULL);
    assert(alloc_stats.malloc_calls > 0);
    
    alloc_stats.fail_malloc = 0;
    
    printf("Allocator failure tests passed!\n");
}

/* Test multiple configurations with different allocators */
static void
test_multiple_configs(void)
{
    printf("Testing multiple configurations with different allocators...\n");
    
    /* Create two configurations */
    jose_cfg_auto_t *cfg1 = jose_cfg();
    jose_cfg_auto_t *cfg2 = jose_cfg();
    assert(cfg1 != NULL);
    assert(cfg2 != NULL);
    
    /* Set different allocators for each */
    int ret1 = jose_cfg_set_alloc(cfg1, test_malloc, test_realloc, test_free);
    assert(ret1 == 0);
    
    /* cfg2 uses default allocators (NULL) */
    
    /* Verify allocators are set correctly */
    jose_malloc_t malloc_func1 = NULL, malloc_func2 = NULL;
    jose_cfg_get_alloc(cfg1, &malloc_func1, NULL, NULL);
    jose_cfg_get_alloc(cfg2, &malloc_func2, NULL, NULL);
    
    assert(malloc_func1 == test_malloc);
    assert(malloc_func2 == NULL);
    
    reset_alloc_stats();
    
    /* Use cfg1 with custom allocators */
    void *buf1 = NULL;
    size_t len1 = 0;
    jose_io_t *io1 = jose_io_malloc(cfg1, &buf1, &len1);
    assert(io1 != NULL);
    
    size_t custom_malloc_calls = alloc_stats.malloc_calls;
    assert(custom_malloc_calls > 0);
    
    /* Use cfg2 with default allocators */
    void *buf2 = NULL;
    size_t len2 = 0;
    jose_io_t *io2 = jose_io_malloc(cfg2, &buf2, &len2);
    assert(io2 != NULL);
    
    /* malloc_calls should not increase since cfg2 uses default malloc */
    assert(alloc_stats.malloc_calls == custom_malloc_calls);
    
    /* Clean up */
    jose_io_decref(io1);
    jose_io_decref(io2);
    
    printf("Multiple configurations test passed!\n");
}

/* Test NULL cfg behavior */
static void
test_null_config(void)
{
    printf("Testing NULL configuration behavior...\n");
    
    /* Test with NULL cfg - should use default allocators */
    void *buf = NULL;
    size_t len = 0;
    
    reset_alloc_stats();
    
    jose_io_t *io = jose_io_malloc(NULL, &buf, &len);
    assert(io != NULL);
    
    /* Custom allocators should not be called */
    assert(alloc_stats.malloc_calls == 0);
    assert(alloc_stats.realloc_calls == 0);
    assert(alloc_stats.free_calls == 0);
    
    /* Test writing data */
    const char *test_data = "Test data";
    assert(io->feed(io, test_data, strlen(test_data)));
    assert(io->done(io));
    
    /* Still no custom allocator calls */
    assert(alloc_stats.malloc_calls == 0);
    assert(alloc_stats.realloc_calls == 0);
    assert(alloc_stats.free_calls == 0);
    
    /* Verify data */
    assert(buf != NULL);
    assert(len == strlen(test_data));
    assert(memcmp(buf, test_data, len) == 0);
    
    jose_io_decref(io);
    
    printf("NULL configuration test passed!\n");
}

/* Test allocator behavior with JWS operations */
static void
test_allocator_with_jws(void)
{
    printf("Testing custom allocators with JWS operations...\n");
    
    jose_cfg_auto_t *cfg = jose_cfg();
    assert(cfg != NULL);
    
    int ret = jose_cfg_set_alloc(cfg, test_malloc, test_realloc, test_free);
    assert(ret == 0);
    
    reset_alloc_stats();
    
    /* Generate a key using custom config */
    json_auto_t *jwk = json_pack("{s:s}", "alg", "HS256");
    assert(jwk != NULL);
    assert(jose_jwk_gen(cfg, jwk));
    
    /* Create and sign a JWS */
    json_auto_t *jws = json_pack("{s:s}", "payload", "test payload");
    assert(jws != NULL);
    assert(jose_jws_sig(cfg, jws, NULL, jwk));
    
    /* Verify the signature */
    assert(jose_jws_ver(cfg, jws, NULL, jwk, false));
    
    /* Check that custom allocators were used */
    printf("  JWS operations - malloc calls: %zu, realloc calls: %zu, free calls: %zu\n",
           alloc_stats.malloc_calls, alloc_stats.realloc_calls, alloc_stats.free_calls);
    
    printf("Custom allocators with JWS operations test passed!\n");
}

int
main(int argc, char *argv[])
{
    printf("Running custom allocator tests for JOSE library...\n\n");
    
    test_allocator_set_get();
    test_allocator_io_operations();
    test_allocator_failures();
    test_multiple_configs();
    test_null_config();
    test_allocator_with_jws();
    
    printf("\nAll custom allocator tests passed successfully!\n");
    
    return EXIT_SUCCESS;
}
