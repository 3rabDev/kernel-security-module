// lsm_hook.c
/*
 * Simple Kernel Security Module for process monitoring
 * Author: 3ràb (Roshdy)
 * Description: Monitors file access and process execution
 */

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("3ràb");
MODULE_DESCRIPTION("Basic security module for monitoring");

/* Log file access attempts */
static int hook_file_permission(struct file *file, int mask)
{
    char comm[TASK_COMM_LEN];
    
    if (mask & MAY_READ) {
        get_task_comm(comm, current);
        printk(KERN_INFO "LSM: Process %s (PID: %d) is reading file\n", 
               comm, current->pid);
    }
    
    if (mask & MAY_WRITE) {
        get_task_comm(comm, current);
        printk(KERN_ALERT "LSM: ⚠️ Write attempt by %s (PID: %d)\n", 
               comm, current->pid);
    }
    
    return 0; /* Always allow */
}

/* Monitor process execution */
static int hook_bprm_check_security(struct linux_binprm *bprm)
{
    char comm[TASK_COMM_LEN];
    
    get_task_comm(comm, current);
    printk(KERN_INFO "LSM: Process %s (PID: %d) executing: %s\n", 
           comm, current->pid, bprm->filename);
    
    return 0;
}

/* Define our hooks */
static struct security_hook_list lsm_hooks[] = {
    LSM_HOOK_INIT(file_permission, hook_file_permission),
    LSM_HOOK_INIT(bprm_check_security, hook_bprm_check_security),
};

/* Module initialization */
static int __init lsm_module_init(void)
{
    printk(KERN_INFO "LSM: Security module loaded successfully\n");
    security_add_hooks(lsm_hooks, ARRAY_SIZE(lsm_hooks), "simple_lsm");
    return 0;
}

/* Module cleanup */
static void __exit lsm_module_exit(void)
{
    printk(KERN_INFO "LSM: Security module unloaded\n");
}

module_init(lsm_module_init);
module_exit(lsm_module_exit);
