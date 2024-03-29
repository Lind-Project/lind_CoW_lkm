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
#include <linux/pgtable.h>
#include <linux/swapops.h>
#include <linux/gfp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jonathan Singer");
MODULE_DESCRIPTION("A LKM that allows for user-space CoW functionality");
MODULE_VERSION("0.1");

#define minimum(x, y) ((x) < (y) ? (x) : (y))
#define maximum(x, y) ((x) > (y) ? (x) : (y))
#define p4dalloc(a, b, c) (unlikely(pgd_none(*(b)) && p4da((a), (b), (c))) ? NULL : p4d_offset((b), (c)))
#define pudalloc(a, b, c) (unlikely(p4d_none(*(b)) && puda((a), (b), (c))) ? NULL : pud_offset((b), (c)))
#define pmdalloc(a, b, c) (unlikely(pud_none(*(b)) && pmda((a), (b), (c))) ? NULL : pmd_offset((b), (c)))
#undef pte_alloc
#define pte_alloc(mm, pmd) (unlikely(pmd_none(*(pmd))) && ptea(mm, pmd))
#define cmpol_put(p) if(p) mpp(p)
#define do_or_clear_bad(ptype) \
static inline int ptype ## _none_or_clear_bad_cow(ptype ## _t *ptype) { \
  if(ptype ## _none(*ptype)) \
    return 1; \
  if(unlikely(ptype ## _bad(*ptype))) { \
    ptype ## cb(ptype); \
    return 1; \
  } \
  return 0; \
}

//for syscall table juggling
void* klnaddr;
unsigned long (*kln)(const char* name);
unsigned long* syscall_table;
ssize_t (*old_vm_writev)(const struct pt_regs*);

//declarations to be populated by kallsyms lookup name
typeof(&reset_vma_resv_huge_pages) rvhp;
typeof(&anon_vma_fork) avf;
typeof(&track_pfn_copy) tpc;
typeof(&vma_interval_tree_insert) viti;
void (*ftmr)(struct mm_struct*, unsigned long, unsigned long, unsigned int, bool);//typeof didn't work
typeof(&__p4d_alloc) p4da;
typeof(&__pud_alloc) puda;
typeof(&__pmd_alloc) pmda;
typeof(&__pte_alloc) ptea;
typeof(&pgd_clear_bad) pgdcb;
typeof(&p4d_clear_bad) p4dcb;
typeof(&pud_clear_bad) pudcb;
typeof(&pmd_clear_bad) pmdcb;
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
typeof(&__vma_link_rb) vmalrb;
typeof(&lru_cache_add_inactive_or_unevictable) lcaiou;
typeof(&__mmu_notifier_invalidate_range_start) mnirs;
typeof(&__mmu_notifier_invalidate_range_end) mnire;
typeof(&add_swap_count_continuation) ascc;
typeof(&swap_duplicate) swdup;
typeof(&cgroup_throttle_swaprate) cgts;
typeof(&mem_cgroup_charge) mcgc;
typeof(&do_munmap) dmm;

do_or_clear_bad(pgd)
do_or_clear_bad(p4d)
do_or_clear_bad(pud)
do_or_clear_bad(pmd)

//Get address of kallsyms_lookup_name, from https://github.com/zizzu0/LinuxKernelModules
static int __kprobes pre0(struct kprobe *p, struct pt_regs *regs) {
  klnaddr = (void*) --regs->ip;
  return 0;
}
static int __kprobes pre1(struct kprobe *p, struct pt_regs *regs) {
  return 0;
}
static void lookup_lookup_name(void) {
  struct kprobe kp0 = {.symbol_name = "kallsyms_lookup_name", .pre_handler = pre0};
  struct kprobe kp1 = {.symbol_name = "kallsyms_lookup_name", .pre_handler = pre1};
  register_kprobe(&kp0);
  register_kprobe(&kp1);
  unregister_kprobe(&kp0);
  unregister_kprobe(&kp1);
  kln = (unsigned long(*)(const char*))klnaddr;
}

static inline void custom_mmu_notifier_invalidate_range_start(struct mmu_notifier_range* range) {
  might_sleep();
  lock_map_acquire(&__mmu_notifier_invalidate_range_start_map);
  if(mm_has_notifiers(range->mm)) {
    range->flags |= MMU_NOTIFIER_RANGE_BLOCKABLE;
    mnirs(range);
  }
  lock_map_release(&__mmu_notifier_invalidate_range_start_map);
}
static inline void custom_mmu_notifier_invalidate_range_end(struct mmu_notifier_range* range) {
  if(mmu_notifier_range_blockable(range))
    might_sleep();
  if(mm_has_notifiers(range->mm))
    mnire(range, false);
}

static int custom_find_vma_links(struct mm_struct *mm, unsigned long addr, unsigned long end, struct vm_area_struct **pprev, struct rb_node ***rb_link, struct rb_node **rb_parent) {
    struct rb_node **__rb_link, *__rb_parent, *rb_prev;
    __rb_link = &mm->mm_rb.rb_node;
    rb_prev = __rb_parent = NULL;

    while(*__rb_link) {
      struct vm_area_struct *vma_tmp;
      __rb_parent = *__rb_link;
      vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);
      if(vma_tmp->vm_end > addr) {
        if(vma_tmp->vm_start < end)
          return -ENOMEM;
        __rb_link = &__rb_parent->rb_left;
      } else {
        rb_prev = __rb_parent;
        __rb_link = &__rb_parent->rb_right;
      }
    }
    *pprev = NULL;
    if(rb_prev)
      *pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
    *rb_link = __rb_link;
    *rb_parent = __rb_parent;
    return 0;
}


static void custom_vma_link(struct vm_area_struct *rvma, struct vm_area_struct *lvma, struct vm_area_struct *prev, 
		            struct rb_node **rb_link, struct rb_node *rb_parent) {
  struct file *mapfile = rvma->vm_file;
  struct address_space *mapping = NULL;
  struct mm_struct* memm = rvma->vm_mm;

  if(mapfile) {
    mapping = mapfile->f_mapping;
    i_mmap_lock_write(mapping);

    get_file(mapfile);
    if(rvma->vm_flags & VM_DENYWRITE)
      put_write_access(file_inode(mapfile));
    if(rvma->vm_flags & VM_SHARED)
      mapping_allow_writable(mapping);

    flush_dcache_mmap_lock(mapping);
    viti(rvma, &mapping->i_mmap);
    flush_dcache_mmap_unlock(mapping);

    i_mmap_unlock_write(mapping);
  } //__vma_link_file

  {
    struct vm_area_struct *next;
    rvma->vm_prev =  prev;
    if(prev) {
      next = prev->vm_next;
      prev->vm_next = rvma;
    } else {
      next = memm->mmap;
      memm->mmap = rvma;
    }
    rvma->vm_next = next;
    if(next)
      next->vm_prev = rvma;
  } //__vma_link_list(current->mm, rvma, prev);

  vmalrb(memm, rvma, rb_link, rb_parent);

  memm->map_count++;
  //validate_mm(memm); //we do not validate
}

static inline int custom_munmap_vma_range(struct mm_struct *mm, unsigned long start, unsigned long len, 
                              struct vm_area_struct **pprev, struct rb_node ***link, 
                              struct rb_node **parent, struct list_head *uf) {
  while(custom_find_vma_links(mm, start, start + len, pprev, link, parent)) {
    if(dmm(mm, start, len, uf))
      return -ENOMEM;
  }
  return 0;
}

static inline struct page* custom_page_copy_prealloc(struct mm_struct *src_mm, struct vm_area_struct *vma, unsigned long addr) {
  struct page *new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, addr);
  if(!new_page)
    return NULL;
  if(mcgc(new_page, src_mm, GFP_KERNEL)) {
    put_page(new_page);
    return NULL;
  }
  cgts(new_page, GFP_KERNEL);
  return new_page;
}

static int custom_copy_present_pte(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma, 
                       pte_t *dst_pte, pte_t *src_pte, unsigned long dstaddr, unsigned long srcaddr, 
           int *rss, struct page **prealloc) {
  struct mm_struct *src_mm = src_vma->vm_mm;
  unsigned long vm_flags = src_vma->vm_flags;
  pte_t pte = *src_pte;
  struct page *page;

  page = vnp(src_vma, srcaddr, pte);
  if(page) {
    struct page *new_page;
    //If these branches are taken, the page need not be allocated
    if(!((vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE))
      goto page_copied;
    if(likely(!atomic_read(&src_mm->has_pinned)))
      goto page_copied;
    if(likely(!page_maybe_dma_pinned(page)))
      goto page_copied;

    //otherwise manually assign+copy preallocated page at pte
    //if none exists, return with -EAGAIN so that calling code can allocate one
    new_page = *prealloc;
    if(!new_page)
      return -EAGAIN;
    *prealloc = NULL;
    copy_user_highpage(new_page, page, dstaddr, src_vma);
    __SetPageUptodate(new_page);
    panar(new_page, dst_vma, dstaddr, false);
    lcaiou(new_page, dst_vma);
    rss[mm_counter(new_page)]++;

    pte = mk_pte(new_page, dst_vma->vm_page_prot);
    pte = maybe_mkwrite(pte_mkdirty(pte), dst_vma);
    set_pte_at(dst_vma->vm_mm, dstaddr, dst_pte, pte);
    return 0;

page_copied:
    get_page(page);
    page_dup_rmap(page, false);
    rss[mm_counter(page)]++;
  }

  if(((vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE) && pte_write(pte)) {
    ptep_set_wrprotect(src_mm, srcaddr, src_pte);
    pte = pte_wrprotect(pte);
  }

  if(vm_flags & VM_SHARED)
    pte = pte_mkclean(pte);
  pte = pte_mkold(pte);

  if(!(vm_flags = VM_UFFD_WP))
    pte = pte_clear_uffd_wp(pte);
  set_pte_at(dst_vma->vm_mm, dstaddr, dst_pte, pte);
  return 0;
}

static unsigned long custom_copy_nonpresent_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm, 
                                                pte_t *dst_pte, pte_t *src_pte, struct vm_area_struct *vma, 
                                                unsigned long dstaddr, unsigned long srcaddr, int* rss) {
  unsigned long vm_flags = vma->vm_flags;
  pte_t pte = *src_pte;
  struct page *page;
  swp_entry_t entry = pte_to_swp_entry(pte);

  if(likely(!non_swap_entry(entry))) {
    if(swdup(entry) < 0)
      return entry.val;
    rss[MM_SWAPENTS]++;
  } else if(is_migration_entry(entry)) {
    page = migration_entry_to_page(entry);
    rss[mm_counter(page)]++;
    if(is_write_migration_entry(entry) && (vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE) {
      make_migration_entry_read(&entry);
      pte = swp_entry_to_pte(entry);
      if(pte_swp_soft_dirty(*src_pte))
        pte = pte_swp_mksoft_dirty(pte);
      if(pte_swp_uffd_wp(*src_pte))
        pte = pte_swp_mkuffd_wp(pte);
      set_pte_at(src_mm, srcaddr, src_pte, pte);
    }
  } else if(is_device_private_entry(entry)) {
    page = device_private_entry_to_page(entry);
    get_page(page);
    rss[mm_counter(page)]++;
    page_dup_rmap(page, false);
    if(is_write_device_private_entry(entry) && (vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE) {
      make_device_private_entry_read(&entry);
      pte = swp_entry_to_pte(entry);
      if(pte_swp_uffd_wp(*src_pte))
        pte = pte_swp_mkuffd_wp(pte);
      set_pte_at(src_mm, srcaddr, src_pte, pte);
    }
  }
  set_pte_at(dst_mm, dstaddr, dst_pte, pte);
  return 0;
}

static int general_copy_pte_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
                      pmd_t *dst_pmd, pmd_t *src_pmd,
                      unsigned long dstaddr, unsigned long srcaddr,
                      unsigned long dstend, unsigned long srcend) {
  pte_t *orig_src_pte, *orig_dst_pte;
  pte_t *src_pte, *dst_pte;
  spinlock_t *src_ptl, *dst_ptl;
  int progress, ret = 0;
  int rss[NR_MM_COUNTERS];
  swp_entry_t entry = (swp_entry_t){0};
  struct page* prealloc = NULL;
  struct mm_struct *dst_mm = dst_vma->vm_mm;
  struct mm_struct *src_mm = src_vma->vm_mm;
again:
  if(srcaddr >= srcend || dstaddr >= dstend)
    return 0;
  progress = 0;
  memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);

  dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, dstaddr, &dst_ptl);
  if(!dst_pte) {
    ret = -ENOMEM;
    goto out;
  }
  src_pte = pte_offset_map(src_pmd, srcaddr);
  src_ptl = pte_lockptr(src_mm, src_pmd);
  if(src_ptl != dst_ptl) 
    spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
  orig_src_pte = src_pte;
  orig_dst_pte = dst_pte;
  arch_enter_lazy_mmu_mode();
  do {
    if(progress >= 32) {
      progress = 0;

      if(need_resched() || spin_needbreak(dst_ptl) || (src_ptl == dst_ptl ? 0 : spin_needbreak(src_ptl)))
        break;
    }
    if(pte_none(*src_pte)) {
      progress++;
      continue;
    }
    if(unlikely(!pte_present(*src_pte))) {
      entry.val = custom_copy_nonpresent_pte(dst_mm, src_mm, dst_pte, src_pte, src_vma, dstaddr, srcaddr, rss);
      if(entry.val)
        break;
      progress += 8;
      continue;
    }
    ret = custom_copy_present_pte(dst_vma, src_vma, dst_pte, src_pte, dstaddr, srcaddr, rss, &prealloc);
    if(unlikely(ret == -EAGAIN))
      break;
    if(unlikely(prealloc)) {
      put_page(prealloc);
      prealloc = NULL;
    }
    progress += 8;
  } while(dst_pte++, src_pte++, srcaddr += PAGE_SIZE, dstaddr += PAGE_SIZE, srcaddr != srcend && dstaddr != dstend);
  arch_leave_lazy_mmu_mode();
  if(src_ptl != dst_ptl)
    spin_unlock(src_ptl);
  pte_unmap(orig_src_pte);
  {
    int i;
    if(current->mm == dst_mm) {
      for(i = 0; i < NR_MM_COUNTERS; i++) {
        if(current->rss_stat.count[i]) {
          long count = atomic_long_add_return(current->rss_stat.count[i], &dst_mm->rss_stat.count[i]);
          mtrs(dst_mm, i, count);
          current->rss_stat.count[i] = 0;
        }
      } //sync_mm_rss
      current->rss_stat.events = 0;
    }
    for(i = 0; i < NR_MM_COUNTERS; i++) {
      if(rss[i]) {
        long count = atomic_long_add_return(rss[i], &dst_mm->rss_stat.count[i]);
        mtrs(dst_mm, i, count);
      }
    }
  } //add_mm_rss_vec
  pte_unmap_unlock(orig_dst_pte, dst_ptl);
  cond_resched();

  if(entry.val) {
    if(ascc(entry, GFP_KERNEL) < 0) {
      ret = -ENOMEM;
      goto out;
    }
    entry.val = 0;
  } else if(ret) {
    WARN_ON_ONCE(ret != -EAGAIN);
    prealloc = custom_page_copy_prealloc(src_mm, src_vma, srcaddr);
    if(!prealloc)
      return -ENOMEM;
    ret = 0;
  }
  if(srcaddr != srcend)
    goto again;
out:
  if(unlikely(prealloc))
    put_page(prealloc);
  return ret;
}

static int general_copy_pmd_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
                                  pud_t *dst_pud, pud_t *src_pud,
                                  unsigned long dstaddr, unsigned long srcaddr,
                                  unsigned long dstend, unsigned long srcend) {
  struct mm_struct *dst_mm = dst_vma->vm_mm;
  pmd_t *src_pmd, *dst_pmd;
  unsigned long pmd_src_next, pmd_dst_next;
  int ret;
  dst_pmd = pmdalloc(dst_mm, dst_pud, dstaddr);
  if(!dst_pmd)
    return -ENOMEM;
  src_pmd = pmd_offset(src_pud, srcaddr);
  while(srcaddr != srcend && dstaddr != dstend) {
    pmd_src_next = pmd_addr_end(srcaddr, srcend);
    pmd_dst_next = pmd_addr_end(dstaddr, dstend);
    if(is_swap_pmd(*src_pmd) || pmd_trans_huge(*src_pmd) || pmd_devmap(*src_pmd))
      return -EINVAL;
    if(!pmd_none_or_clear_bad_cow(src_pmd))
      if((ret = general_copy_pte_range(dst_vma, src_vma, dst_pmd, src_pmd, dstaddr, srcaddr, pmd_dst_next, pmd_src_next)))
        return ret;
    if(pmd_src_next - srcaddr > pmd_dst_next - dstaddr) {
      dst_pmd++;
      srcaddr += pmd_dst_next - dstaddr;
      dstaddr = pmd_dst_next;
    } else if(pmd_src_next - srcaddr < pmd_dst_next - dstaddr) {
      src_pmd++;
      dstaddr += pmd_src_next - srcaddr;
      srcaddr = pmd_src_next;
    } else {
      dst_pmd++, src_pmd++, srcaddr = pmd_src_next, dstaddr = pmd_dst_next;
    }
  }

  return 0;
}

static int general_copy_pud_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
                                  p4d_t *dst_p4d, p4d_t *src_p4d,
                                  unsigned long dstaddr, unsigned long srcaddr,
                                  unsigned long dstend, unsigned long srcend) {
  struct mm_struct *dst_mm = dst_vma->vm_mm;
  pud_t *src_pud, *dst_pud;
  int ret;
  unsigned long pud_src_next, pud_dst_next;
  dst_pud = pudalloc(dst_mm, dst_p4d, dstaddr);
  if(!dst_pud)
    return -ENOMEM;
  src_pud = pud_offset(src_p4d, srcaddr);
  while(srcaddr != srcend && dstaddr != dstend) {
    pud_src_next = pud_addr_end(srcaddr, srcend);
    pud_dst_next = pud_addr_end(dstaddr, dstend);
    if(pud_trans_huge(*src_pud) || pud_devmap(*src_pud)) 
      return -EINVAL;
    if(!pud_none_or_clear_bad_cow(src_pud))
      if((ret = general_copy_pmd_range(dst_vma, src_vma, dst_pud, src_pud, dstaddr, srcaddr, pud_dst_next, pud_src_next)))
        return ret;
    if(pud_src_next - srcaddr > pud_dst_next - dstaddr) {
      dst_pud++;
      srcaddr += pud_dst_next - dstaddr;
      dstaddr = pud_dst_next;
    } else if(pud_src_next - srcaddr < pud_dst_next - dstaddr) {
      src_pud++;
      dstaddr += pud_src_next - srcaddr;
      srcaddr = pud_src_next;
    } else {
      dst_pud++, src_pud++, srcaddr = pud_src_next, dstaddr = pud_dst_next;
    }
  }
  return 0;
}

static int general_copy_p4d_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
                                  pgd_t *dst_pgd, pgd_t *src_pgd,
                                  unsigned long dstaddr, unsigned long srcaddr,
                                  unsigned long dstend, unsigned long srcend) {
  struct mm_struct *dst_mm = dst_vma->vm_mm;
  p4d_t *src_p4d, *dst_p4d;
  int ret;
  unsigned long p4d_src_next, p4d_dst_next;
  dst_p4d = p4dalloc(dst_mm, dst_pgd, dstaddr);
  if(!dst_p4d)
    return -ENOMEM;
  src_p4d = p4d_offset(src_pgd, srcaddr);
  while(srcaddr != srcend && dstaddr != dstend) {
    p4d_src_next = p4d_addr_end(srcaddr, srcend);
    p4d_dst_next = p4d_addr_end(dstaddr, dstend);
    if(!p4d_none_or_clear_bad_cow(src_p4d))
      if((ret = general_copy_pud_range(dst_vma, src_vma, dst_p4d, src_p4d, dstaddr, srcaddr, p4d_dst_next, p4d_src_next)))
        return ret;
    if(p4d_src_next - srcaddr > p4d_dst_next - dstaddr) {
      dst_p4d++;
      srcaddr += p4d_dst_next - dstaddr;
      dstaddr = p4d_dst_next;
    } else if(p4d_src_next - srcaddr < p4d_dst_next - dstaddr) {
      src_p4d++;
      dstaddr += p4d_src_next - srcaddr;
      srcaddr = p4d_src_next;
    } else {
      dst_p4d++, src_p4d++, srcaddr = p4d_src_next, dstaddr = p4d_dst_next;
    }
  }
  return 0;
}

static int general_copy_pgd_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
                                  unsigned long dstaddr, unsigned long srcaddr,
                                  unsigned long dstend, unsigned long srcend) {
  unsigned long srcnext, dstnext;
  struct mm_struct *dst_mm = dst_vma->vm_mm;
  struct mm_struct *src_mm = src_vma->vm_mm;
  pgd_t *src_pgd = pgd_offset(src_mm, srcaddr);
  pgd_t *dst_pgd = pgd_offset(dst_mm, dstaddr);
  int ret;
  while(srcaddr != srcend && dstaddr != dstend) {
    srcnext = pgd_addr_end(srcaddr, srcend);
    dstnext = pgd_addr_end(dstaddr, dstend);
    if(!pgd_none_or_clear_bad_cow(src_pgd))
      if((ret = general_copy_p4d_range(dst_vma, src_vma, dst_pgd, src_pgd, dstaddr, srcaddr, dstnext, srcnext)))
        return ret;
    if(srcnext - srcaddr > dstnext - dstaddr) {
      dst_pgd++;
      srcaddr += dstnext - dstaddr;
      dstaddr = dstnext;
    } else if(srcnext - srcaddr < dstnext - dstaddr) {
      src_pgd++;
      dstaddr += srcnext - srcaddr;
      srcaddr = srcnext;
    } else {
      dst_pgd++, src_pgd++, srcaddr = srcnext, dstaddr = dstnext;
    }
  }
  return 0;
}

int custom_copy_page_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
                           unsigned long dstaddr, unsigned long srcaddr,
                           unsigned long dstend, unsigned long srcend) {
  struct mm_struct *dst_mm = dst_vma->vm_mm;
  struct mm_struct *src_mm = src_vma->vm_mm;
  struct mmu_notifier_range range;
  bool is_cow;
  int ret;
  if(src_mm != dst_mm)
    return -ENOTSUPP;
  if(!(src_vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP)) && !src_vma->anon_vma)
    return 0;
  if(is_vm_hugetlb_page(src_vma))
    return -EINVAL;
  if(unlikely(src_vma->vm_flags & VM_PFNMAP)) {
    ret = tpc(src_vma);
    if(ret)
      return ret;
  }

  //mmap_write_lock(dst_mm);
  is_cow = (src_vma->vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
  if(is_cow) {
    mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE, 0, src_vma, src_mm, srcaddr, srcend);
    custom_mmu_notifier_invalidate_range_start(&range);
    lockdep_assert_held_write(src_mm->mmap_lock);//mmap_assert_write_locked(src_mm);
    raw_write_seqcount_begin(&src_mm->write_protect_seq);
  }

  ret = general_copy_pgd_range(dst_vma, src_vma, dstaddr, srcaddr, dstend, srcend);

  if(is_cow) {
    raw_write_seqcount_end(&src_mm->write_protect_seq);
    custom_mmu_notifier_invalidate_range_end(&range);
  }
  //mmap_write_unlock(dst_mm);
  return ret;
}

ssize_t process_vm_cowv(const struct pt_regs *regs) {
  const __user struct iovec *local_iov = (struct iovec*) regs->si;
  const __user struct iovec *remote_iov = (struct iovec*) regs->r10;
  unsigned long liovcnt = regs->dx;
  unsigned long riovcnt = regs->r8;
  struct iovec *local_iov_kern = kmalloc(sizeof(struct iovec) * liovcnt, GFP_KERNEL);
  struct iovec *remote_iov_kern = kmalloc(sizeof(struct iovec) * riovcnt, GFP_KERNEL);
  pid_t pid = regs->di;
  struct task_struct* local_task = current;

  ssize_t copied_count = 0;
  int retval;
  int i;
  struct vm_area_struct *lvma, *rvma, *prev;
  struct rb_node **rb_link, *rb_parent;
  LIST_HEAD(uf);

  if(liovcnt != riovcnt || liovcnt > UIO_MAXIOV) {
    retval = -EINVAL;
    printk(KERN_INFO "LINDLKM: error in iovecs input, input and output vector have different lengths\n");
    goto out;
  }

  if(copy_from_user(local_iov_kern, local_iov, liovcnt * sizeof(struct iovec))) {
    retval = -EFAULT;
    goto out;
  }
  if(copy_from_user(remote_iov_kern, remote_iov, riovcnt * sizeof(struct iovec))) {
    retval = -EFAULT;
    goto out;
  }
  
  //First let's confirm that the pid is actually the current pid!
  //To do this we check what pid the current task has within its namespace and 
  //check that against the provided pid!
  if(task_tgid_vnr(current) != pid) {
    retval = -EINVAL;
    printk(KERN_INFO "LINDLKM: PID %d (vpid) of remote process is not PID %d (vpid) of calling process\n", task_tgid_vnr(current), pid);
    goto out;
  }

  //validate input vectors
  for(i = 0; i < liovcnt; i++) {
    if(local_iov_kern[i].iov_len != remote_iov_kern[i].iov_len) {
      retval = -EINVAL;
      printk(KERN_INFO "LINDLKM: error in iovecs input, corresponding elements are different lengths\n");
      goto out;
    }
    if(!local_iov_kern[i].iov_base || !remote_iov_kern[i].iov_base) {
      retval = -EINVAL;
      printk(KERN_INFO "LINDLKM: error in iovecs input, input has a null address\n");
      goto out;
    }
    if((unsigned long) remote_iov_kern[i].iov_base & (PAGE_SIZE-1) || remote_iov_kern[i].iov_len & (PAGE_SIZE-1) || 
       (unsigned long) local_iov_kern[i].iov_base & (PAGE_SIZE-1) || local_iov_kern[i].iov_len & (PAGE_SIZE-1)) {
      retval = -EINVAL;
      printk(KERN_INFO "LINDLKM: error in iovecs input, address not page aligned or length not a multiple of page length\n");
      goto out;
    }
    if((unsigned long) remote_iov_kern[i].iov_base >= TASK_SIZE_MAX || 
       (unsigned long) (remote_iov_kern[i].iov_base + remote_iov_kern[i].iov_len) >= TASK_SIZE_MAX || 
       (unsigned long) local_iov_kern[i].iov_base >= TASK_SIZE_MAX || 
       (unsigned long) (local_iov_kern[i].iov_base + local_iov_kern[i].iov_len) >= TASK_SIZE_MAX) {
      retval = -EINVAL;
      printk(KERN_INFO "LINDLKM: error in iovecs input, address not canonical or in kernel address space\n");
      goto out;
    }
    if((unsigned long) remote_iov_kern[i].iov_base <= (unsigned long) local_iov_kern[i].iov_base) {
      if((unsigned long) remote_iov_kern[i].iov_base + remote_iov_kern[i].iov_len > (unsigned long) local_iov_kern[i].iov_base) {
        retval = -EINVAL;
        printk(KERN_INFO "LINDLKM: error in iovecs input, corresponding mappings overlap\n");
        goto out;
      }
    } else if((unsigned long) local_iov_kern[i].iov_base + local_iov_kern[i].iov_len > (unsigned long) remote_iov_kern[i].iov_base) {
      retval = -EINVAL;
      printk(KERN_INFO "LINDLKM: error in iovecs input, corresponding mappings overlap\n");
      goto out;
    }
  }

  mmap_write_lock(current->mm);
  //perform copy, finding vmas in the range and copying them accordingly
  for(i = 0; i < liovcnt; i++) {
    unsigned long localstart = (unsigned long)local_iov_kern[i].iov_base;
    unsigned long localend = localstart + local_iov_kern[i].iov_len;
    unsigned long remotestart = (unsigned long)remote_iov_kern[i].iov_base;
    unsigned long copyto, tountil, copyfrom, fromuntil;
    if(localstart == localend) continue;

    if((retval = custom_munmap_vma_range(local_task->mm, remotestart, remote_iov_kern[i].iov_len, &prev, &rb_link, &rb_parent, &uf)))
      goto undoall_norvma;

anothervma:
    lvma = find_vma_intersection(local_task->mm, localstart, localend);
    if(!lvma)
      continue;

    if(lvma->vm_flags & VM_DONTCOPY) {
      localstart = lvma->vm_end;
      goto anothervma;
    }

    if(fatal_signal_pending(current)) {
      retval = -EINTR;
      goto undoall_norvma;
    }
    if(lvma->vm_flags & VM_ACCOUNT) {
      unsigned long len = vma_pages(lvma);
      if(svmemm(local_task->mm, len)) {
        retval = -ENOMEM;
        goto undoall_norvma;
      }
    }

    rvma = vmad(lvma);
    if(!rvma) {
      retval = -ENOMEM;
      goto undoall_norvma;
    }
    rvma->vm_start = maximum(lvma->vm_start - (long unsigned) local_iov_kern[i].iov_base + (long unsigned) remote_iov_kern[i].iov_base, (long unsigned) remotestart);
    rvma->vm_end = rvma->vm_start + minimum(lvma->vm_end - maximum(lvma->vm_start, (long unsigned) local_iov_kern[i].iov_base),                                             remote_iov_kern[i].iov_len - maximum(0, rvma->vm_start - remotestart));
    rvma->vm_pgoff += (maximum((long unsigned) local_iov_kern[i].iov_base, lvma->vm_start) - lvma->vm_start) >> PAGE_SHIFT;

    retval = vmadpol(lvma, rvma);
    if(retval) {
      retval = -ENOMEM;
      goto undoall;
    }
    rvma->vm_mm = current->mm;

    retval = dufd(rvma, &uf);
    if(retval) {
      retval = -ENOMEM;
      goto undoall;
    }

    if(rvma->vm_flags & VM_WIPEONFORK)
      rvma->anon_vma = NULL;
    else if(avf(rvma, lvma)) {
      retval = -ENOMEM;
      goto mpolout;
    }
    rvma->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);
    if(is_vm_hugetlb_page(rvma)) {
      retval = -EINVAL;
      goto mpolout; //hugetlb pages are not supported!
    }

    custom_vma_link(rvma, lvma, prev, rb_link, rb_parent);
    vmstata(current->mm, rvma->vm_flags, vma_pages(rvma));

    copyto = rvma->vm_start;
    tountil = rvma->vm_end;
    copyfrom = maximum(localstart,lvma->vm_start);
    fromuntil = copyfrom + (tountil - copyto);
    if(!(rvma->vm_flags & VM_WIPEONFORK)) {
      copied_count += tountil - copyto;
      retval = custom_copy_page_range(rvma, lvma, copyto, copyfrom, tountil, fromuntil);
    }
    if(rvma->vm_ops && rvma->vm_ops->open)
      rvma->vm_ops->open(rvma);
    if(retval)
      goto undoall_norvma;
    ftmr(local_task->mm, copyfrom, fromuntil, PAGE_SHIFT, false);

    if(localstart < localend) {
      unsigned long linkbegin;
      unsigned long linkend;
      localstart = lvma->vm_end;
      linkbegin = remotestart + localstart - (unsigned long) local_iov_kern[i].iov_base;
      linkend = remotestart + local_iov_kern[i].iov_len;
      custom_find_vma_links(local_task->mm, linkbegin, linkend, &prev, &rb_link, &rb_parent);
      goto anothervma;
    }
  }
  mmap_write_unlock(current->mm);
  dufdc(&uf);
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  return copied_count;
mpolout:
  cmpol_put(vma_policy(rvma));
undoall:
  vmaf(rvma);
undoall_norvma:
  printk(KERN_INFO "LINDLKM: error %d in page allocation, bailing out\n", retval);
  for(i = 0; i < liovcnt; i++) {
    custom_munmap_vma_range(current->mm, (unsigned long) remote_iov_kern[i].iov_base, 
                            remote_iov_kern[i].iov_len, &prev, &rb_link, &rb_parent, &uf);
    //failure happens transparently
  }
  mmap_write_unlock(current->mm);
out:
  kfree(local_iov_kern);
  kfree(remote_iov_kern);
  return retval;
}

ssize_t intercept_process_vm_writev(const struct pt_regs *regs) {
  if(regs->r9 & 0x20) {
    printk(KERN_INFO "LINDLKM: intercepted vm writev, will CoW");
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
  enable_syscall_write();
  old_vm_writev = (ssize_t (*)(const struct pt_regs *)) syscall_table[__NR_process_vm_writev];
  syscall_table[__NR_process_vm_writev] = (unsigned long) intercept_process_vm_writev;
  disable_syscall_write();
  rvhp = (typeof(&reset_vma_resv_huge_pages)) kln("reset_vma_resv_huge_pages");
  avf = (typeof(&anon_vma_fork)) kln("anon_vma_fork");
  viti = (typeof(&vma_interval_tree_insert)) kln("vma_interval_tree_insert");
  ftmr = (void (*)(struct mm_struct*, unsigned long, unsigned long, unsigned int, bool)) kln("flush_tlb_mm_range");
  p4da = (typeof(&__p4d_alloc)) kln("__p4d_alloc");
  puda = (typeof(&__pud_alloc)) kln("__pud_alloc");
  pmda = (typeof(&__pmd_alloc)) kln("__pmd_alloc");
  ptea = (typeof(&__pte_alloc)) kln("__pte_alloc");
  pgdcb = (typeof(&pgd_clear_bad)) kln("pgd_clear_bad");
  p4dcb = (typeof(&p4d_clear_bad)) kln("p4d_clear_bad");
  pudcb = (typeof(&pud_clear_bad)) kln("pud_clear_bad");
  pmdcb = (typeof(&pmd_clear_bad)) kln("pmd_clear_bad");
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
  vmalrb = (typeof(&__vma_link_rb)) kln("__vma_link_rb");
  lcaiou = (typeof(&lru_cache_add_inactive_or_unevictable)) kln("lru_cache_add_inactive_or_unevictable");
  mnirs = (typeof(&__mmu_notifier_invalidate_range_start)) kln("__mmu_notifier_invalidate_range_start");
  mnire = (typeof(&__mmu_notifier_invalidate_range_end)) kln("__mmu_notifier_invalidate_range_end");
  ascc = (typeof(&add_swap_count_continuation)) kln("add_swap_count_continuation");
  swdup = (typeof(&swap_duplicate)) kln("swap_duplicate");
  cgts = (typeof(&cgroup_throttle_swaprate)) kln("cgroup_throttle_swaprate");
  mcgc = (typeof(&mem_cgroup_charge)) kln("mem_cgroup_charge");
  dmm = (typeof(&do_munmap)) kln("do_munmap");
  printk(KERN_INFO "LINDLKM: cowcall LKM initialized\n");
  return 0;
}

static void __exit cowcall_exit(void){
  printk(KERN_INFO "LINDLKM: cowcall LKM unloading\n");
  enable_syscall_write();
  syscall_table[__NR_process_vm_writev] = (unsigned long) old_vm_writev;
  disable_syscall_write();
  printk(KERN_INFO "LINDLKM: cowcall LKM unloaded\n");
}

module_init(cowcall_init);
module_exit(cowcall_exit);
