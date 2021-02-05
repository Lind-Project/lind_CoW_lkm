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
#include <linux/swap.h>
#include <linux/userfaultfd_k.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jonathan Singer");
MODULE_DESCRIPTION("A LKM that allows for user-space CoW functionality");
MODULE_VERSION("0.1");

#define p4dalloc(a, b, c) (unlikely(pgd_none(*(b)) && p4da((a), (b), (c))) ? NULL : p4d_offset((b), (c)))
#define pudalloc(a, b, c) (unlikely(p4d_none(*(b)) && puda((a), (b), (c))) ? NULL : pud_offset((b), (c)))
#define pmdalloc(a, b, c) (unlikely(pud_none(*(b)) && pmda((a), (b), (c))) ? NULL : pmd_offset((b), (c)))
#undef pte_alloc
#define pte_alloc(mm, pmd) (unlikely(pmd_none(*(pmd))) && ptea(mm, pmd))
#define cmpol_put(p) if(p) mpp(p)

void* klnaddr;
unsigned long (*kln)(const char* name);
unsigned long* syscall_table;
ssize_t (*old_vm_writev)(const struct pt_regs*);

typeof(&reset_vma_resv_huge_pages) rvhp;
typeof(&anon_vma_fork) avf;
typeof(&insert_vm_struct) ivs;
typeof(&track_pfn_copy) tpc;
typeof(&vma_interval_tree_insert_after) vitia;
void (*ftmr)(struct mm_struct*, unsigned long, unsigned long, unsigned int, bool);
typeof(&__p4d_alloc) p4da;
typeof(&__pud_alloc) puda;
typeof(&__pmd_alloc) pmda;
typeof(&__pte_alloc) ptea;
typeof(&mm_trace_rss_stat) mtrs;
typeof(&page_add_new_anon_rmap) panar;
typeof(&vm_normal_page) vnp;
typeof(&__mpol_put) mpp;
typeof(&dup_userfaultfd) dufd;
typeof(&dup_userfaultfd_complete) dufdc;
typeof(&vm_area_free) vmaf;
typeof(&vm_area_dup) vmad;
typeof(&vma_dup_policy) vmadpol;
typeof(&security_vm_enough_memory_mm) svmemm;
typeof(&vm_stat_account) vmstata;

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

int custom_copy_present_pte(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma, pte_t *dst_pte, pte_t *src_pte, unsigned long addr, unsigned long srcaddr, int *rss, struct page **prealloc) {
	struct mm_struct *src_mm = src_vma->vm_mm;
	unsigned long vm_flags = src_vma->vm_flags;
	pte_t pte = *src_pte;
	struct page *page;

	page = vnp(src_vma, srcaddr, pte);
	if(page) {
		int retval;
		//copy_present_page here
		struct page* new_page;
		if(!((vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE)) {retval = 1; goto page_copied;}
		if(likely(!atomic_read(&src_mm->has_pinned))) {retval = 1; goto page_copied;}
		if(likely(!page_maybe_dma_pinned(page))) {retval = 1; goto page_copied;}
		new_page = *prealloc;
		if(!new_page) {retval = -EAGAIN; goto page_copied;}
		*prealloc = NULL;
		copy_user_highpage(new_page, page, addr, src_vma);
		__SetPageUptodate(new_page);
		panar(new_page, dst_vma, addr, false);
		rss[mm_counter(new_page)]++;

		pte = mk_pte(new_page, dst_vma->vm_page_prot);
		pte = maybe_mkwrite(pte_mkdirty(pte), dst_vma);
		set_pte_at(dst_vma->vm_mm, addr, dst_pte, pte);
		retval = 0;
page_copied:

		if(retval <= 0) return retval;
		get_page(page);
		page_dup_rmap(page, false);
		rss[mm_counter(page)]++;
	}

	if(((vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE) && pte_write(pte)) {
		ptep_set_wrprotect(src_mm, srcaddr, src_pte);
		pte = pte_wrprotect(pte);
	}

	if(vm_flags & VM_SHARED) pte = pte_mkclean(pte);
	pte = pte_mkold(pte);

	if(!(vm_flags = VM_UFFD_WP)) pte = pte_clear_uffd_wp(pte);
	set_pte_at(dst_vma->vm_mm, addr, dst_pte, pte);
	return 0;
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
	pmd_t *src_pmd, *dst_pmd;
	unsigned long p4d_dst_next, p4d_src_next;
	unsigned long pud_dst_next, pud_src_next;
	unsigned long pmd_dst_next, pmd_src_next;
	if(src_mm != dst_mm) return -ENOTSUPP;
	if(!(src_vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP)) && !src_vma->anon_vma)
		return 0;
	if(is_vm_hugetlb_page(src_vma))
		return 0; //we don't handle hugetlb pages yet
	if(unlikely(src_vma->vm_flags & VM_PFNMAP)) {
		ret = tpc(src_vma);
		if(ret) return ret;
	}

	mmap_write_lock(dst_mm);
	is_cow = (src_vma->vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
	if(is_cow) {
		//can we do mmu_notifier stuff here?
		raw_write_seqcount_begin(&src_mm->write_protect_seq);
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

				dst_pmd = pmdalloc(dst_mm, dst_pud, srcaddr);
				if(!dst_pmd) break; //error out better
				src_pmd = pmd_offset(src_pud, srcaddr);
			  printk(KERN_INFO "LINDLKM: pmd did it\n");
				do {
					pmd_src_next = pmd_addr_end(srcaddr, pud_src_next);
					pmd_dst_next = pmd_addr_end(dstaddr, pud_dst_next);
					if(pmd_trans_huge(*src_pmd) || pmd_devmap(*src_pmd)) break; //we don't care about hugepages
          if(is_swap_pmd(*src_pmd)) 
						; //not sure how to handle swapped out pages?
				  if(pmd_none(*src_pmd) || pmd_bad(*src_pmd)) continue;

					{
            pte_t *orig_src_pte, *orig_dst_pte;
            pte_t *src_pte, *dst_pte;
						spinlock_t *src_ptl, *dst_ptl;
						int progress, ret = 0;
						int *rss;
						swp_entry_t entry = (swp_entry_t){0};
						struct page* prealloc = NULL;
again:
						progress = 0;
						rss = (int*) get_mm_rss(dst_mm);
						dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, dstaddr, &dst_ptl);
						if(!dst_pte) break; //error out better
						src_pte = pte_offset_map(src_pmd, srcaddr);
						src_ptl = pte_lockptr(src_mm, src_pmd);
						spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
						orig_src_pte = src_pte;
						orig_dst_pte = dst_pte;
						arch_enter_lazy_mmu_mode();
						do {
							if(progress >= 32) {
								progress = 0;
								if(need_resched() || spin_needbreak(src_ptl) || spin_needbreak(dst_ptl)) break;//source of error?
							}
							if(pte_none(*src_pte)) {
								progress++;
								continue;
							}
							if(unlikely(!pte_present(*src_pte))) {
						    printk(KERN_INFO "LINDLKM: copying nonpresent pte\n");
								break; //we'll need to do copy_nonpresent_pte
								//entry.val = copy_nonpresent_pte(dst_mm, src_mm, dst_pte, src_pte, src_vma, dstaddr, rss);
								if(entry.val) break;
								progress += 8;
								continue;
							}
						  printk(KERN_INFO "LINDLKM: copying present pte\n");
							ret = custom_copy_present_pte(dst_vma, src_vma, dst_pte, src_pte, dstaddr, srcaddr, rss, &prealloc);
							if(unlikely(ret == -EAGAIN)) break;
							if(unlikely(prealloc)) {
								put_page(prealloc);
								prealloc = NULL;
							}
							progress += 8;
						} while(dst_pte++, src_pte++, srcaddr += PAGE_SIZE, dstaddr += PAGE_SIZE, srcaddr != pmd_src_next);
						arch_leave_lazy_mmu_mode();
						spin_unlock(src_ptl);
						pte_unmap(orig_src_pte); //??
						pte_unmap_unlock(orig_dst_pte, dst_ptl);
						cond_resched();

						if(entry.val) {
							if(add_swap_count_continuation(entry, GFP_KERNEL) < 0) {
								ret = -ENOMEM;
								goto out;
							}
							entry.val = 0;
						} else if(ret) {
							WARN_ON_ONCE(ret != -EAGAIN);
							//prealloc = page_copy_prealloc(src_mm, src_vma, srcaddr);
							//handle page_copy_prealloc
							if(!prealloc) break; //error out better
							ret = 0;
						}
						if(srcaddr != pmd_src_next) goto again;
out:
						if(unlikely(prealloc)) put_page(prealloc);
					} //copy_pte_range

				} while(dst_pmd++, src_pmd++, srcaddr = pmd_src_next, dstaddr = pmd_dst_next, srcaddr != pud_src_next);
      } while(dst_pud++, src_pud++, srcaddr = pud_src_next, dstaddr = pud_dst_next, srcaddr != p4d_src_next);
    } while(dst_p4d++, src_p4d++, srcaddr = p4d_src_next, dstaddr = p4d_dst_next, srcaddr != srcnext);
    printk(KERN_INFO "LINDLKM: did full range?\n");
  } while (dst_pgd++, src_pgd++, srcaddr = srcnext, dstaddr = dstnext, srcaddr != srcend);
  if(is_cow) {
    raw_write_seqcount_end(&src_mm->write_protect_seq);
    //flushing cache range would be a no-op on x86
  }
  mmap_write_unlock(dst_mm);
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
  struct vm_area_struct *lvma, *rvma;
	LIST_HEAD(uf);
  //ignore flags
  //TODO: ERSCH and EPERM support

  if(liovcnt != riovcnt) {
    retval = -EINVAL;
		goto out;
  }

  printk(KERN_INFO "LINDLKM: copying from user\n");
  retval = copy_from_user(local_iov_kern, local_iov, liovcnt * sizeof(struct iovec));
  retval = copy_from_user(remote_iov_kern, remote_iov, riovcnt * sizeof(struct iovec));
  
  remote_task = pid_task(find_vpid(pid), PIDTYPE_PID);
  printk(KERN_INFO "LINDLKM: got task\n");
  for(i = 0; i < liovcnt; i++) {
    if(local_iov_kern[i].iov_len != remote_iov_kern[i].iov_len) {
      retval = -EINVAL;
			goto out;
		}
    if(find_vma_intersection(remote_task->mm, (unsigned long) remote_iov_kern[i].iov_base, 
	       (unsigned long) (remote_iov_kern[i].iov_base + remote_iov_kern[i].iov_len))) {
      retval = -EFAULT;
			goto out;
    }
    if(!find_exact_vma(local_task->mm, (unsigned long) local_iov_kern[i].iov_base, 
            (unsigned long) (local_iov_kern[i].iov_base + local_iov_kern[i].iov_len))) {
      retval = -EFAULT;
			goto out;
    }
  }
  printk(KERN_INFO "LINDLKM: got iovs\n");
  //Any attempt to lock here (required by copy_page_range) causes deadlock and I don't know why
  for(i = 0; i < liovcnt; i++) {
		unsigned int charge;
    bool need_rmap_locks;
    struct file *file;
		rvma = NULL;
		lvma = find_exact_vma(local_task->mm, (unsigned long) local_iov_kern[i].iov_base, 
		    (unsigned long) (local_iov_kern[i].iov_base + local_iov_kern[i].iov_len));
    printk(KERN_INFO "LINDLKM: got lvma\n");
		if(lvma->vm_flags & VM_DONTCOPY) {
			vmstata(local_task->mm, lvma->vm_flags, -vma_pages(lvma));
			continue;
		}

		charge = 0;

		if(fatal_signal_pending(current)) {
			retval = -EINTR;
			goto out;
		}
		if(lvma->vm_flags & VM_ACCOUNT) {
			unsigned long len = vma_pages(lvma);
			if(svmemm(local_task->mm, len)) {
			  retval = -ENOMEM;
			  goto out;
			}
			charge = len;
		}


		rvma = vmad(lvma);
    if(!rvma) {
			retval = -ENOMEM;
      goto out;
		}
		rvma->vm_start = (long unsigned) remote_iov_kern[i].iov_base;
    rvma->vm_end = rvma->vm_start + remote_iov_kern[i].iov_len;
    printk(KERN_INFO "LINDLKM: duping\n");

		retval = vmadpol(lvma, rvma);
		if(retval) {
			retval = -ENOMEM;
			goto out;
		}
    printk(KERN_INFO "LINDLKM: polduping\n");
		rvma->vm_mm = remote_task->mm;

		retval = dufd(rvma, &uf); //does this need to be done??
		if(retval) {
			retval = -ENOMEM;
			goto mpolout;
		}
    printk(KERN_INFO "LINDLKM: userfd stuff\n");

    if(rvma->vm_flags & VM_WIPEONFORK)
      rvma->anon_vma = NULL;
    else if(avf(rvma, lvma)) {
			retval = -ENOMEM;
      goto mpolout;
		}
    rvma->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);
    file = rvma->vm_file;
    printk(KERN_INFO "LINDLKM: not file backed\n");
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
    printk(KERN_INFO "LINDLKM: huge page\n");
    if(is_vm_hugetlb_page(rvma))
      goto mpolout; //hugetlb pages are not supported!
    printk(KERN_INFO "LINDLKM: hugetlb check finished\n");

		//vma linking stuff

    if(!(rvma->vm_flags & VM_WIPEONFORK)) {
      printk(KERN_INFO "LINDLKM: %p %p \n", rvma, lvma);
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
    ftmr(local_task->mm, lvma->vm_start, lvma->vm_end, PAGE_SHIFT, false);
  }
	dufdc(&uf);
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  if(copied_count == 0) return -1;//TODO: error better here?
  return copied_count;
mpolout:
	cmpol_put(vma_policy(rvma));
  out:
	if(rvma) vmaf(rvma);
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  return retval;
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
  rvhp = (typeof(&reset_vma_resv_huge_pages)) kln("reset_vma_resv_huge_pages");
  avf = (typeof(&anon_vma_fork)) kln("anon_vma_fork");
  ivs = (typeof(&insert_vm_struct)) kln("insert_vm_struct");
  vitia = (typeof(&vma_interval_tree_insert_after)) kln("vma_interval_tree_insert_after");
  ftmr = (void (*)(struct mm_struct*, unsigned long, unsigned long, unsigned int, bool)) kln("flush_tlb_mm_range");
  p4da = (typeof(&__p4d_alloc)) kln("__p4d_alloc");
  puda = (typeof(&__pud_alloc)) kln("__pud_alloc");
  pmda = (typeof(&__pmd_alloc)) kln("__pmd_alloc");
  ptea = (typeof(&__pte_alloc)) kln("__pte_alloc");
	mtrs = (typeof(&mm_trace_rss_stat)) kln("mm_trace_rss_stat");
  panar = (typeof(&page_add_new_anon_rmap)) kln("page_add_new_anon_rmap");
  vnp = (typeof(&vm_normal_page)) kln("vm_normal_page");
	tpc = (typeof(&track_pfn_copy)) kln("track_pfn_copy");
  mpp = (typeof(&__mpol_put)) kln("__mpol_put");
  dufd = (typeof(&dup_userfaultfd)) kln("dup_userfaultfd");
  dufdc = (typeof(&dup_userfaultfd_complete)) kln("dup_userfaultfd_complete");
	vmaf = (typeof(&vm_area_free)) kln("vm_area_free");
	vmad = (typeof(&vm_area_dup)) kln("vm_area_dup");
  vmadpol = (typeof(&vma_dup_policy)) kln("vma_dup_policy");
	svmemm = (typeof(&security_vm_enough_memory_mm)) kln("security_vm_enough_memory_mm");
	vmstata = (typeof(&vm_stat_account)) kln("vm_stat_account");
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
