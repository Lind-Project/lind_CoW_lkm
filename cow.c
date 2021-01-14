#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/rmap.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/kprobes.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jonathan Singer");
MODULE_DESCRIPTION("A LKM that allows for user-space CoW functionality");
MODULE_VERSION("0.1");

void* klnaddr;
unsigned long (*kln)(const char* name);
unsigned long* syscall_table;
void (*rvhp)(void*);
int (*cpr)(void*, void*);
int (*avf)(void*, void*);
void* (*vmd)(void*);
int (*ivs)(void*, void*);
void* (*cvma)(void*, unsigned long, unsigned long, pgoff_t, void*);
ssize_t (*old_vm_writev)(const struct pt_regs *);
void (*vitia)(void*, void*, void*);

//Get address of kallsyms_lookup_name, from https://github.com/zizzu0/LinuxKernelModules
static int __kprobes pre0(struct kprobe *p, struct pt_regs *regs) {
  klnaddr = (void*) --regs->ip;
  return 0;
}
static int __kprobes pre1(struct kprobe *p, struct pt_regs *regs) {
  return 0;
}
static void do_register_kprobe(struct kprobe *kp, char *symbol_name, void* handler) {
  kp->symbol_name = symbol_name;
  kp->pre_handler = handler;
  register_kprobe(kp);
}
void lookup_lookup_name(void) {
  struct kprobe kp0, kp1;
  do_register_kprobe(&kp0, "kallsyms_lookup_name", pre0);
  do_register_kprobe(&kp1, "kallsyms_lookup_name", pre1);
  unregister_kprobe(&kp0);
  unregister_kprobe(&kp1);
  kln = (unsigned long(*)(const char*))klnaddr;
}

ssize_t process_vm_cowv(const struct pt_regs *regs) {
  int retval;
  pid_t pid = regs->di;
  const __user struct iovec *local_iov = (struct iovec*) regs->si;
  unsigned long liovcnt = regs->dx;
  struct iovec *local_iov_kern = kmalloc(sizeof(struct iovec), liovcnt);
  const __user struct iovec *remote_iov = (struct iovec*) regs->r10;
  unsigned long riovcnt = regs->r8;
  struct iovec *remote_iov_kern = kmalloc(sizeof(struct iovec), riovcnt);
  struct task_struct* local_task = current;
  struct task_struct* remote_task;
  ssize_t copied_count = 0;
  int i;
  //ignore flags
  //TODO: ERSCH and EPERM support

  if(!local_task) {
    return -ENOMEM;
  }
  if(liovcnt != riovcnt) {
    goto cow_pre_einval;
  }

  copy_from_user(local_iov_kern, local_iov, liovcnt * sizeof(struct iovec));
  copy_from_user(remote_iov_kern, remote_iov, riovcnt * sizeof(struct iovec));
  
  remote_task = pid_task(find_vpid(pid), PIDTYPE_PID);
  for(i = 0; i < liovcnt; i++) {
    if(local_iov_kern[i].iov_len != remote_iov_kern[i].iov_len)
      goto cow_pre_einval;
    if(find_vma_intersection(remote_task->mm, (unsigned long) remote_iov_kern[i].iov_base, 
	       (unsigned long) (remote_iov_kern[i].iov_base + remote_iov_kern[i].iov_len)) || 
       !find_exact_vma(local_task->mm, (unsigned long) local_iov_kern[i].iov_base, 
	       (unsigned long) (local_iov_kern[i].iov_base + local_iov_kern[i].iov_len)))
      goto cow_pre_efault;
  }
  //There may be deadlock potential here
  mmap_write_lock_nested(remote_task->mm, SINGLE_DEPTH_NESTING);
  if(local_task->mm != remote_task->mm) {
    mmap_write_lock_nested(local_task->mm, SINGLE_DEPTH_NESTING);
  }
  for(i = 0; i < liovcnt; i++) {
    bool need_rmap_locks;
    struct vm_area_struct *lvma = find_exact_vma(local_task->mm, (unsigned long) local_iov_kern[i].iov_base, 
		    (unsigned long) (local_iov_kern[i].iov_base + local_iov_kern[i].iov_len));
    unsigned long pgoff = (unsigned long) remote_iov_kern[i].iov_base >> PAGE_SHIFT;
    struct vm_area_struct *rvma = cvma(&lvma, (unsigned long) remote_iov_kern[i].iov_base, local_iov_kern[i].iov_len, pgoff, &need_rmap_locks);
    struct file *file;
    if(!rvma)
      goto cow_enomem;
    rvma->vm_mm = remote_task->mm;
    if(rvma->vm_flags & VM_WIPEONFORK)
      rvma->anon_vma = NULL;
    else if(avf(rvma, lvma))
      goto cow_enomem;
    rvma->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);
    file = rvma->vm_file;
    if(file) {
      struct inode *inode = file_inode(file);
      struct address_space *mapping = file->f_mapping;
      get_file(file);
      if(rvma->vm_flags & VM_DENYWRITE)
        atomic_dec(&inode->i_writecount);
      i_mmap_lock_write(mapping);
      if(rvma->vm_flags & VM_SHARED)
        atomic_dec(&mapping->i_mmap_writable);
      flush_dcache_mmap_lock(mapping);
      vitia(rvma, lvma, &mapping->i_mmap);
      flush_dcache_mmap_unlock(mapping);
      i_mmap_unlock_write(mapping);
    }
    if(is_vm_hugetlb_page(rvma))
      rvhp(rvma);
    if(!(rvma->vm_flags & VM_WIPEONFORK))
      retval = cpr(lvma, rvma);
    if(rvma->vm_ops && rvma->vm_ops->open)
      rvma->vm_ops->open(rvma);
    if(retval) ;//TODO: error out in some not braindead way
    retval = ivs(remote_task->mm, rvma);
    if(retval) ;//TODO: error out in some not braindead way
    copied_count += local_iov_kern[i].iov_len;
  }
  mmap_write_unlock(remote_task->mm);
  if(local_task->mm != remote_task->mm) {
    mmap_write_unlock(local_task->mm);
  }
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  if(copied_count == 0) return -1;//TODO: error better here?
  return copied_count;
  cow_enomem:
  mmap_write_unlock(remote_task->mm);
  if(local_task->mm == remote_task->mm) {
    mmap_write_unlock(local_task->mm);
  }
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  return -ENOMEM;
  cow_pre_einval:
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  return -EINVAL;
  cow_pre_efault:
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  return -EFAULT;
}

ssize_t intercept_process_vm_writev(const struct pt_regs *regs) {
  printk(KERN_INFO "LINDLKM: vm writev at %p intercepted with args %d %p %ld %p %ld %ld", old_vm_writev, (int) regs->di, (void*) regs->si, regs->dx, (void*) regs->r10, regs->r8, regs->r9);
  if(regs->r9 & 0x20) {
    printk(KERN_INFO "LINDLKM: intercepted and skipping vm writev");
    return process_vm_cowv(regs);
  } else {
    return old_vm_writev(regs);
  }
}

void enable_syscall_write(void) {
  unsigned long cr0val;
  unsigned int level;
  pte_t* pte = lookup_address((unsigned long) syscall_table, &level);
  preempt_disable();
  asm volatile("mov %%cr0, %0": "=r" (cr0val));
  cr0val &= ~0x00010000;
  asm volatile("mov %0, %%cr0": :"r" (cr0val));
  asm volatile("cli");
  pte->pte |= _PAGE_RW;
}
void disable_syscall_write(void) {
  unsigned long cr0val;
  unsigned int level;
  pte_t* pte = lookup_address((unsigned long) syscall_table, &level);
  pte->pte &= ~_PAGE_RW;
  asm volatile("mov %%cr0, %0": "=r" (cr0val));
  cr0val |= 0x00010000;
  asm volatile("mov %0, %%cr0": :"r" (cr0val));
  asm volatile("sti");
  preempt_enable();
}

static int __init cowcall_init(void) {
  lookup_lookup_name();
  printk(KERN_INFO "LINDLKM: cowcall LKM initializing\n");
  syscall_table = (unsigned long*) kln("sys_call_table");
  printk(KERN_INFO "LINDLKM: Syscall table at %p\n", syscall_table);
  enable_syscall_write();
  old_vm_writev = (ssize_t (*)(const struct pt_regs *)) syscall_table[__NR_process_vm_writev];
  syscall_table[__NR_process_vm_writev] = (unsigned long) intercept_process_vm_writev;
  disable_syscall_write();
  printk(KERN_INFO "LINDLKM: Old vm writev at %p\n", old_vm_writev);
  rvhp = (void(*)(void*)) kln("reset_vma_resv_huge_pages");
  cpr = (int(*)(void*, void*)) kln("copy_page_range");
  avf = (int(*)(void*, void*)) kln("anon_vma_fork");
  vmd = (void*(*)(void*)) kln("vm_area_dup");
  ivs = (int(*)(void*, void*)) kln("insert_vm_struct");
  cvma = (void* (*)(void*, unsigned long, unsigned long, pgoff_t, void*)) kln("copy_vma");
  vitia = (void (*)(void*, void*, void*))kln("vma_interval_tree_insert_after");
  return 0;
}

static void __exit cowcall_exit(void){
  printk(KERN_INFO "LINDLKM: cowcall LKM unloading\n");
  enable_syscall_write();
  syscall_table[__NR_process_vm_writev] = (unsigned long) old_vm_writev;
  disable_syscall_write();
}

module_init(cowcall_init);
module_exit(cowcall_exit);
