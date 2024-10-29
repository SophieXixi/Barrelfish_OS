
/*
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <spawn/elfimg.h>

/**
 * @brief initializes the elfimg structure from the multiboot module
 *
 * @param[out] img     elfimg structure to be initialized
 * @param[in]  module
 *
 */
void elfimg_init_from_module(struct elfimg *img, struct mem_region *module)
{
    // Step 1: Create a capability reference for the module
    struct capref module_cap = {
        .cnode = cnode_module,
        .slot = module->mrmod_slot
    };

    // Step 2: Get the module size
    size_t module_size = module->mrmod_size;

    // Step 3: Initialize the elfimg structure with the module capability
    elfimg_init_with_cap(img, module_cap, module_size);

    printf("ELF image initialized with module size: %zu bytes\n", module_size);
}


/**
 * @brief destroys the elfimg structure, returning its backing memory capability if any
 *
 * @param[in]  img  elfimg structure to be destroyed
 * @param[out] mem  returns the capability of the elfimg structure
 *
 * @return SYS_ERR_OK on success, error value on failure
 */
errval_t elfimg_destroy(struct elfimg *img, struct capref *mem)
{
    errval_t err;
    *mem = img->mem;

    err = elfimg_unmap(img);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_UNMAP_MODULE);
    }
    memset(img, 0, sizeof(*img));
    return SYS_ERR_OK;
}


/**
 * @brief maps the elfimg structure into the current address space
 *
 * @param[in] img  elfimg structure to be mapped
 *
 * @return SYS_ERR_OK on success, LIB_ERR_* on failure
 *
 * Note: only map the memory if it is not already mapped and has a capability
 */
errval_t elfimg_map(struct elfimg *img)
{
    if (img->buf != NULL) {
        return SYS_ERR_OK;
    }

    size_t map_size = ROUND_UP(img->size, BASE_PAGE_SIZE);
    return paging_map_frame(get_current_paging_state(), &img->buf, map_size, img->mem);
}


/**
 * @brief unmaps a previously mapped elfimg structure
 *
 * @param[in] img  elfimg structure to be unmapped
 *
 * @return SYS_ERR_OK on success, LIB_ERR_* on failure
 *
 * Note: only unmap the memory if it is backed by a supplied capability
 */
errval_t elfimg_unmap(struct elfimg *img)
{
    errval_t err;

    if (img->buf == NULL || capref_is_null(img->mem)) {
        return SYS_ERR_OK;
    }

    err = paging_unmap(get_current_paging_state(), img->buf);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_MEMOBJ_UNMAP_REGION);
    }

    img->buf = NULL;
    return SYS_ERR_OK;
}

