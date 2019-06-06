/*
 * QEMU-Orbital user interface
 *
 * Copyright (c) 2019-2019 Nick Renieris
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef UI_orbital_procs_list_LIST_H_
#define UI_orbital_procs_list_LIST_H_


#ifdef __cplusplus
extern "C" {
#endif

struct proc;
struct vmspace;
struct orbital_procs_list_t;

#ifdef __cplusplus
namespace freebsd {
#include "freebsd/sys/sys/proc.h"
#include "freebsd/sys/vm/vm_map.h"
}  // namespace freebsd

struct orbital_proc_data {
    struct freebsd::proc proc;
    struct freebsd::vmspace vmspace;  // unused until we find its offset
};
using thread = freebsd::thread;
#else
struct orbital_proc_data;
#endif

struct orbital_procs_list_t *orbital_procs_list_create(void);

void orbital_procs_list_destroy(struct orbital_procs_list_t *procs_list);

void orbital_procs_list_add_proc(struct orbital_procs_list_t *procs_list,
                                 struct orbital_proc_data *p);

void orbital_procs_list_add_proc_thread(struct orbital_procs_list_t *procs_list,
                                        int owner_pid,
#ifndef __cplusplus
                                        struct
#endif
                                        thread *td);

void orbital_procs_list_clear(struct orbital_procs_list_t *procs_list);

void orbital_procs_list_draw(struct orbital_procs_list_t *procs_list, const char *title, bool* p_open);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // UI_orbital_procs_list_LIST_H_
