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
#include <linux/mmu_notifier.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jonathan Singer");
MODULE_DESCRIPTION("A LKM that allows for user-space CoW functionality");
MODULE_VERSION("0.1");

#define p4dalloc(a, b, c) (unlikely(pgd_none(*(b)) && p4da((a), (b), (c))) ? NULL : p4d_offset((b), (c)))
#define pudalloc(a, b, c) (unlikely(p4d_none(*(b)) && puda((a), (b), (c))) ? NULL : pud_offset((b), (c)))

void* klnaddr;
unsigned long (*kln)(const char* name);
unsigned long* syscall_table;
void (*rvhp)(void*);
int (*avf)(void*, void*);
int (*ivs)(void*, void*);
void* (*cvma)(void*, unsigned long, unsigned long, pgoff_t, void*);
ssize_t (*old_vm_writev)(const struct pt_regs *);
void (*vitia)(void*, void*, void*);
void (*ftmr)(void*, unsigned long, unsigned long, int, bool);
p4d_t *(*p4da)(void*, void*, unsigned long);
pud_t *(*puda)(void*, void*, unsigned long);

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

int custom_copy_page_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma) {
  pgd_t *src_pgd, *dst_pgd;
  unsigned long srcnext;
  unsigned long dstnext;
  unsigned long srcaddr = src_vma->vm_start;
  unsigned long srcend = src_vma->vm_end;
  unsigned long dstaddr = dst_vma->vm_start;
  unsigned long dstend = dst_vma->vm_end;
  struct mm_struct *dst_mm = dst_vma->vm_mm;
  struct mm_struct *src_mm = src_vma->vm_mm;
  bool is_cow;
  int ret;
  p4d_t *src_p4d, *dst_p4d;
  pud_t *src_pud, *dst_pud;
  unsigned long p4d_dst_next, p4d_src_next;
  unsigned long pud_dst_next, pud_src_next;
  if(!(src_vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP)) && !src_vma->anon_vma)
    return 0;
  if(is_vm_hugetlb_page(src_vma))
    return 0; //we don't handle hugetlb pages yet
  if(unlikely(src_vma->vm_flags & VM_PFNMAP))
    return 0; //we don't handle pure page regions

  is_cow = (src_vma->vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
  if(is_cow) {
    //I am currently unsure, but I believe this ought to be done to the destination locations?
    mmap_write_lock(src_mm);
    raw_write_seqcount_begin(&src_mm->write_protect_seq);
    mmap_write_unlock(src_mm);
  }

  printk(KERN_INFO "LINDLKM: initial iscow garbage\n");
  ret = 0;
  dst_pgd = pgd_offset(dst_mm, dstaddr);
  src_pgd = pgd_offset(src_mm, srcaddr);
  printk(KERN_INFO "LINDLKM: offsets calculated\n");

  do {
    srcnext = pgd_addr_end(srcaddr, srcend);
    dstnext = pgd_addr_end(dstaddr, dstend);
    if(pgd_none(*src_pgd) || pgd_bad(*src_pgd)) continue; //probably we should clear bad?

    printk(KERN_INFO "LINDLKM: p4d details %p %p %lu\n", dst_mm, dst_pgd, dstaddr);
    dst_p4d = p4dalloc(dst_mm, dst_pgd, dstaddr);
    if(!dst_p4d) break; //error out better
    src_p4d = p4d_offset(src_pgd, srcaddr);
    do {
      p4d_src_next = p4d_addr_end(srcaddr, srcnext);
      p4d_dst_next = p4d_addr_end(dstaddr, dstnext);
      if(p4d_none(*src_p4d) || p4d_bad(*src_p4d)) continue;

      dst_pud = pudalloc(dst_mm, dst_p4d, dstaddr);
      if(!dst_pud) break; //error out better
      src_pud = pud_offset(src_p4d, srcaddr);
      printk(KERN_INFO "LINDLKM: pud did it\n");
      do {
        pud_src_next = pud_addr_end(srcaddr, p4d_src_next);
        pud_dst_next = pud_addr_end(dstaddr, p4d_dst_next);
	if(pud_trans_huge(*src_pud) || pud_devmap(*src_pud)) break; //error out better, we don't support hugetlb pages
	if(pud_none(*src_pud) || pud_bad(*src_pud)) continue;
	//copy_pmd_range then long copy_pte_range and we're out of this hell
      } while(dst_pud++, src_pud++, srcaddr = pud_src_next, dstaddr = pud_dst_next, srcaddr != p4d_src_next);
    } while(dst_p4d++, src_p4d++, srcaddr = p4d_src_next, dstaddr = p4d_dst_next, srcaddr != srcnext);
    printk(KERN_INFO "LINDLKM: did stupid copy?\n");
  } while (dst_pgd++, src_pgd++, srcaddr = srcnext, dstaddr = dstnext, srcaddr != srcend);
  if(is_cow) {
    raw_write_seqcount_end(&src_mm->write_protect_seq);
    printk(KERN_INFO "LINDLKM: does it die on ftmr?\n");
    ftmr(src_vma->vm_mm, src_vma->vm_start, src_vma->vm_end, PAGE_SHIFT, false);
    //flushing cache range would be a no-op on x86
  }
  printk(KERN_INFO "LINDLKM: final iscow garbage\n");
  return ret;
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

  if(liovcnt != riovcnt) {
    goto cow_pre_einval;
  }

  printk(KERN_INFO "LINDLKM: copying from user\n");
  retval = copy_from_user(local_iov_kern, local_iov, liovcnt * sizeof(struct iovec));
  retval = copy_from_user(remote_iov_kern, remote_iov, riovcnt * sizeof(struct iovec));
  
  remote_task = pid_task(find_vpid(pid), PIDTYPE_PID);
  printk(KERN_INFO "LINDLKM: got task\n");
  for(i = 0; i < liovcnt; i++) {
    if(local_iov_kern[i].iov_len != remote_iov_kern[i].iov_len)
      goto cow_pre_einval;
    if(find_vma_intersection(remote_task->mm, (unsigned long) remote_iov_kern[i].iov_base, 
	       (unsigned long) (remote_iov_kern[i].iov_base + remote_iov_kern[i].iov_len))) {
      goto cow_pre_efault;
    }
    if(!find_exact_vma(local_task->mm, (unsigned long) local_iov_kern[i].iov_base, 
            (unsigned long) (local_iov_kern[i].iov_base + local_iov_kern[i].iov_len))) {
      goto cow_pre_efault;
    }
  }
  printk(KERN_INFO "LINDLKM: got iovs\n");
  //Any attempt to lock here (required by copy_page_range) causes deadlock and I don't know why
  for(i = 0; i < liovcnt; i++) {
    bool need_rmap_locks;
    struct vm_area_struct *lvma = find_exact_vma(local_task->mm, (unsigned long) local_iov_kern[i].iov_base, 
		    (unsigned long) (local_iov_kern[i].iov_base + local_iov_kern[i].iov_len));
    unsigned long pgoff = (unsigned long) remote_iov_kern[i].iov_base >> PAGE_SHIFT;
    //Note: BIG BUG! It links it into the wrong vm_mm!! This is likely to make everything not work
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
    printk(KERN_INFO "LINDLKM: not file backed\n");
    if(file) {
      struct inode *inode = file_inode(file);
      struct address_space *mapping = file->f_mapping;
      get_file(file);
      if(rvma->vm_flags & VM_DENYWRITE)
        atomic_dec(&inode->i_writecount);
      //i_mmap_lock_write(mapping);
      if(rvma->vm_flags & VM_SHARED)
        atomic_dec(&mapping->i_mmap_writable);
      //flush_dcache_mmap_lock(mapping);
      vitia(rvma, lvma, &mapping->i_mmap);
      flush_dcache_mmap_unlock(mapping);
      //i_mmap_unlock_write(mapping);
    }
    printk(KERN_INFO "LINDLKM: huge page\n");
    if(is_vm_hugetlb_page(rvma))
      rvhp(rvma);
    printk(KERN_INFO "LINDLKM: hugetlb check finished\n");
    if(!(rvma->vm_flags & VM_WIPEONFORK)) {
      printk(KERN_INFO "LINDLKM: %p %p \n", rvma, lvma);
      //copy page range custom
      retval = custom_copy_page_range(rvma, lvma);
    }
    if(rvma->vm_ops && rvma->vm_ops->open)
      rvma->vm_ops->open(rvma);
    if(retval) ;//TODO: error out in some not braindead way
    printk(KERN_INFO "LINDLKM: something I don't understand finished\n");
    retval = ivs(remote_task->mm, rvma);
    if(retval) ;//TODO: error out in some not braindead way
    printk(KERN_INFO "LINDLKM: something happened??\n");
    copied_count += local_iov_kern[i].iov_len;
    printk(KERN_INFO "LINDLKM: looped right?\n");
  }
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  if(copied_count == 0) return -1;//TODO: error better here?
  return copied_count;
  cow_enomem:
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
  avf = (int(*)(void*, void*)) kln("anon_vma_fork");
  ivs = (int(*)(void*, void*)) kln("insert_vm_struct");
  cvma = (void* (*)(void*, unsigned long, unsigned long, pgoff_t, void*)) kln("copy_vma");
  vitia = (void (*)(void*, void*, void*))kln("vma_interval_tree_insert_after");
  ftmr = (void (*)(void*, unsigned long, unsigned long, int, bool)) kln("flush_tlb_mm_range");
  p4da = (p4d_t *(*)(void*, void*, unsigned long)) kln("__p4d_alloc");
  puda = (pud_t *(*)(void*, void*, unsigned long)) kln("__pud_alloc");
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
