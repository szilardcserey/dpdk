!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


./lib/librte_vhost/vhost_user/fd_man.h

typedef void (*fd_cb)(int fd, void *dat, int *remove);        <========== fd_cb  pointer to a function  file descriptor call back

struct fdentry {
        int fd;         /* -1 indicates this entry is empty */
        fd_cb rcb;      /* callback when this fd is readable. */
        fd_cb wcb;      /* callback when this fd is writeable.*/
        void *dat;      /* fd context */
        int busy;       /* whether this entry is being used in cb. */
};

------------------------------------------------------------


./lib/librte_vhost/vhost_user/fd_man.c:14

/**
 * Register the fd in the fdset with read/write handler and context.
 */
int
fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *dat)
{
        int i;

        if (pfdset == NULL || fd == -1)
                return -1;

        pthread_mutex_lock(&pfdset->fd_mutex);

        /* Find a free slot in the list. */
        i = fdset_find_free_slot(pfdset);
        if (i == -1) {
                pthread_mutex_unlock(&pfdset->fd_mutex);
                return -2;
        }

        fdset_add_fd(pfdset, i, fd, rcb, wcb, dat);
        pfdset->num++;

        pthread_mutex_unlock(&pfdset->fd_mutex);

        return 0;
}


------------------------------------------------------------

./lib/librte_vhost/vhost_user/fd_man.c:75:fdset_add_fd(struct fdset  *pfdset, int idx, int fd,

static void
fdset_add_fd(struct fdset  *pfdset, int idx, int fd,
        fd_cb rcb, fd_cb wcb, void *dat)
{
        struct fdentry *pfdentry;

        if (pfdset == NULL || idx >= MAX_FDS)
                return;

        pfdentry = &pfdset->fd[idx];
        pfdentry->fd = fd;
        pfdentry->rcb = rcb;
        pfdentry->wcb = wcb;
        pfdentry->dat = dat;
}

------------------------------------------------------------

./lib/librte_vhost/vhost_user/fd_man.h

struct fdentry {
        int fd;         /* -1 indicates this entry is empty */
        fd_cb rcb;      /* callback when this fd is readable. */
        fd_cb wcb;      /* callback when this fd is writeable.*/
        void *dat;      /* fd context */
        int busy;       /* whether this entry is being used in cb. */
};



./lib/librte_vhost/vhost_user/fd_man.h

#define MAX_FDS 1024

struct fdset {
        struct fdentry fd[MAX_FDS];
        pthread_mutex_t fd_mutex;
        int num;        /* current fd number of this fdset */
};



!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

-----------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:321:		conn_fd, vserver_message_handler, NULL, ctx);


/* call back when there is new virtio connection.  */
static void
vserver_new_vq_conn(int fd, void *dat, __rte_unused int *remove)
{
        struct vhost_server *vserver = (struct vhost_server *)dat;
        int conn_fd;
        struct connfd_ctx *ctx;
        int fh;
        struct vhost_device_ctx vdev_ctx = { (pid_t)0, 0 };
        unsigned int size;

        conn_fd = accept(fd, NULL, NULL);
        RTE_LOG(INFO, VHOST_CONFIG,
                "new virtio connection is %d\n", conn_fd);
        if (conn_fd < 0)
                return;

        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
                close(conn_fd);
                return;
        }

        fh = ops->new_device(vdev_ctx);
        if (fh == -1) {
                free(ctx);
                close(conn_fd);
                return;
        }

        vdev_ctx.fh = fh;
        size = strnlen(vserver->path, PATH_MAX);
        ops->set_ifname(vdev_ctx, vserver->path,
                size);

        RTE_LOG(INFO, VHOST_CONFIG, "new device, handle is %d\n", fh);

        ctx->vserver = vserver;
        ctx->fh = fh;
        fdset_add(&g_vhost_server.fdset, 
                conn_fd, vserver_message_handler, NULL, ctx);                  <============= vserver_message_handler
}





=================================================================================================================

----------------USER------------------
 0x7ff7fb5f740d : __close_nocancel+0x24/0x57 [/lib/x86_64-linux-gnu/libpthread-2.19.so]
 0x55fff1 : user_destroy_device+0x141/0x170 [/usr/sbin/ovs-vswitchd]
 0x5517a0 : vserver_message_handler+0x1a0/0x550 [/usr/sbin/ovs-vswitchd]



./lib/librte_vhost/vhost_user/vhost-net-user.c:57:static void vserver_message_handler(int fd, void *dat, int *remove);
./lib/librte_vhost/vhost_user/vhost-net-user.c:321:		conn_fd, vserver_message_handler, NULL, ctx);
./lib/librte_vhost/vhost_user/vhost-net-user.c:326:vserver_message_handler(int connfd, void *dat, int *remove)





/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{
        struct vhost_device_ctx ctx;
        struct connfd_ctx *cfd_ctx = (struct connfd_ctx *)dat;
        struct VhostUserMsg msg;
        uint64_t features;
        int ret;

        ctx.fh = cfd_ctx->fh;
        ret = read_vhost_message(connfd, &msg);
        if (ret <= 0 || msg.request >= VHOST_USER_MAX) {
                if (ret < 0)
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read message failed\n");
                else if (ret == 0)
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "vhost peer closed\n");
                else
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read incorrect message\n");

                close(connfd);
                *remove = 1;
                free(cfd_ctx);
                user_destroy_device(ctx);           <======== user_destroy_device
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",
                vhost_message_str[msg.request]);
        switch (msg.request) {
        case VHOST_USER_GET_FEATURES:
                ret = ops->get_features(ctx, &features);
                msg.payload.u64 = features;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_FEATURES:
                features = msg.payload.u64;
                ops->set_features(ctx, &features);
                break;

        case VHOST_USER_GET_PROTOCOL_FEATURES:
                msg.payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_PROTOCOL_FEATURES:
                user_set_protocol_features(ctx, msg.payload.u64);
                break;

        case VHOST_USER_SET_OWNER:
                ops->set_owner(ctx);
                break;
        case VHOST_USER_RESET_OWNER:
                ops->reset_owner(ctx);
                break;

        case VHOST_USER_SET_MEM_TABLE:
                user_set_mem_table(ctx, &msg);
                break;

        case VHOST_USER_SET_LOG_BASE:
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_LOG_FD:
                close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_VRING_NUM:
                ops->set_vring_num(ctx, &msg.payload.state);
                break;
        case VHOST_USER_SET_VRING_ADDR:
                ops->set_vring_addr(ctx, &msg.payload.addr);
                break;
        case VHOST_USER_SET_VRING_BASE:
                ops->set_vring_base(ctx, &msg.payload.state);
                break;

        case VHOST_USER_GET_VRING_BASE:
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);
                break;
        case VHOST_USER_SET_VRING_CALL:
                user_set_vring_call(ctx, &msg);
                break;

        case VHOST_USER_SET_VRING_ERR:
                if (!(msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK))
                        close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented\n");
                break;

        case VHOST_USER_GET_QUEUE_NUM:
                msg.payload.u64 = VHOST_MAX_QUEUE_PAIRS;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_ENABLE:
                user_set_vring_enable(ctx, &msg.payload.state);
                break;

        default:
                break;

        }
}

-----------------------------------------------------------------------------------------
||
\/


./lib/librte_vhost/vhost_user/virtio-net-user.c:342:user_destroy_device(struct vhost_device_ctx ctx)
./lib/librte_vhost/vhost_user/vhost-net-user.c:350:		user_destroy_device(ctx);
./lib/librte_vhost/vhost_user/virtio-net-user.h:58:void user_destroy_device(struct vhost_device_ctx);




void
user_destroy_device(struct vhost_device_ctx ctx)
{
        struct virtio_net *dev = get_device(ctx);

        if (dev && (dev->flags & VIRTIO_DEV_RUNNING))
                notify_ops->destroy_device(dev);

        if (dev && dev->mem) {
                free_mem_region(dev);
                free(dev->mem);           <======== free
                dev->mem = NULL;
        }
}


-----------------------------------------------------------------------------------------
LIBC6/eglibc-2.19
./nptl/sysdeps/unix/sysv/linux/i386/not-cancel.h:34:# define __close_nocancel(fd) __close (fd)

# define __close_nocancel(fd) __close (fd)


-----------------------------------------------------------------------------------------


./lib/librte_vhost/rte_virtio_net.h:122


/**
 * Device structure contains all configuration information relating to the device.
 */
struct virtio_net {
        struct virtio_memory    *mem;           /**< QEMU memory and memory region information. */
        uint64_t                features;       /**< Negotiated feature set. */
        uint64_t                protocol_features;      /**< Negotiated protocol feature set. */
        uint64_t                device_fh;      /**< device identifier. */
        uint32_t                flags;          /**< Device flags. Only used to check if device is running on data core. */
#define IF_NAME_SZ (PATH_MAX > IFNAMSIZ ? PATH_MAX : IFNAMSIZ)
        char                    ifname[IF_NAME_SZ];     /**< Name of the tap device or socket path. */
        uint32_t                virt_qp_nb;     /**< number of queue pair we have allocated */
        void                    *priv;          /**< private context */
        uint64_t                reserved[64];   /**< Reserve some spaces for future extension. */
        struct vhost_virtqueue  *virtqueue[VHOST_MAX_QUEUE_PAIRS * 2];  /**< Contains all virtqueue information. */
} __rte_cache_aligned;




/**
 * Memory structure includes region and mapping information.
 */
struct virtio_memory {
        uint64_t        base_address;   /**< Base QEMU userspace address of the memory file. */
        uint64_t        mapped_address; /**< Mapped address of memory file base in our applications memory space. */
        uint64_t        mapped_size;    /**< Total size of memory file. */
        uint32_t        nregions;       /**< Number of memory regions. */
        struct virtio_memory_regions      regions[0]; /**< Memory region information. */
};




##############################################################################################################
==============================================================================================================


KERNEL

---------------KERNEL-----------------
 0xffffffff811cced0 : free_huge_page+0x0/0x210 [kernel]
 0xffffffff81190b1b : __put_compound_page+0x2b/0x30 [kernel]
 0xffffffff81190b56 : put_compound_page+0x36/0x1a0 [kernel]
 0xffffffff81190cdd : put_page+0x1d/0x50 [kernel]
 0xffffffff812e7098 : remove_inode_hugepages+0x2a8/0x330 [kernel]
 0xffffffff812e713e : hugetlbfs_evict_inode+0x1e/0x40 [kernel]
 0xffffffff8121820e : evict+0xbe/0x1a0 [kernel]
 0xffffffff81218eab : iput+0x19b/0x200 [kernel]
 0xffffffff812147dc : __dentry_kill+0x17c/0x1e0 [kernel]
 0xffffffff812149e9 : dput+0x1a9/0x210 [kernel]
 0xffffffff811ffda8 : __fput+0x188/0x210 [kernel]
 0xffffffff811ffe6e : ____fput+0xe/0x10 [kernel]
 0xffffffff81099fc6 : task_work_run+0x86/0xb0 [kernel]
 0xffffffff81078806 : exit_to_usermode_loop+0x73/0xa2 [kernel]
 0xffffffff81003a6e : syscall_return_slowpath+0x4e/0x60 [kernel]
 0xffffffff817fa658 : int_ret_from_sys_call+0x25/0x8f [kernel]
free_huge_page


./include/linux/hugetlb.h:91:void free_huge_page(struct page *page);
./mm/hugetlb.c:1204:void free_huge_page(struct page *page)


void free_huge_page(struct page *page)
{
        /*
         * Can't pass hstate in here because it is called from the
         * compound page destructor.
         */
        struct hstate *h = page_hstate(page);
        int nid = page_to_nid(page);
        struct hugepage_subpool *spool =
                (struct hugepage_subpool *)page_private(page);
        bool restore_reserve;

        set_page_private(page, 0);
        page->mapping = NULL;
        BUG_ON(page_count(page));
        BUG_ON(page_mapcount(page));
        restore_reserve = PagePrivate(page);
        ClearPagePrivate(page);

        /*
         * A return code of zero implies that the subpool will be under its
         * minimum size if the reservation is not restored after page is free.
         * Therefore, force restore_reserve operation.
         */
        if (hugepage_subpool_put_pages(spool, 1) == 0)
                restore_reserve = true;

        spin_lock(&hugetlb_lock);
        clear_page_huge_active(page);
        hugetlb_cgroup_uncharge_page(hstate_index(h),
                                     pages_per_huge_page(h), page);
        if (restore_reserve)
                h->resv_huge_pages++;

        if (h->surplus_huge_pages_node[nid]) {
                /* remove the page from active list */
                list_del(&page->lru);
                update_and_free_page(h, page);
                h->surplus_huge_pages--;
                h->surplus_huge_pages_node[nid]--;
        } else {
                arch_clear_hugepage_flags(page);
                enqueue_huge_page(h, page);
        }
        spin_unlock(&hugetlb_lock);
}


/\
||

____________________________________________________________________________________________________

./mm/swap.c:76

static void __put_compound_page(struct page *page)
{
        compound_page_dtor *dtor;

        /*
         * __page_cache_release() is supposed to be called for thp, not for
         * hugetlb. This is because hugetlb page does never have PageLRU set
         * (it's never listed to any LRU lists) and no memcg routines should
         * be called for hugetlb (it has a separate hugetlb_cgroup.)
         */
        if (!PageHuge(page))
                __page_cache_release(page);
        dtor = get_compound_page_dtor(page);   
        (*dtor)(page);                                <======== calls "free_huge_page"  through get_compound_page_dtor
}


```````````````````````````````

./include/linux/mm.h:547

static inline compound_page_dtor *get_compound_page_dtor(struct page *page)
{
        VM_BUG_ON_PAGE(page[1].compound_dtor >= NR_COMPOUND_DTORS, page);
        return compound_page_dtors[page[1].compound_dtor];
}


```````````````````````````````
./mm/hugetlb.c:1303

/*
 * PageHuge() only returns true for hugetlbfs pages, but not for normal or
 * transparent huge pages.  See the PageTransHuge() documentation for more
 * details.
 */
int PageHuge(struct page *page)
{
        if (!PageCompound(page))
                return 0;

        page = compound_head(page);
        return page[1].compound_dtor == HUGETLB_PAGE_DTOR;
}
EXPORT_SYMBOL_GPL(PageHuge);



``````````````````````````````

./include/linux/mm.h:534

/* Keep the enum in sync with compound_page_dtors array in mm/page_alloc.c */
enum compound_dtor_id {
        NULL_COMPOUND_DTOR,
        COMPOUND_PAGE_DTOR,
#ifdef CONFIG_HUGETLB_PAGE
        HUGETLB_PAGE_DTOR,
#endif
        NR_COMPOUND_DTORS,
};
extern compound_page_dtor * const compound_page_dtors[];

``````````````````````````````
./include/linux/mm.h

static inline void set_compound_page_dtor(struct page *page,
                enum compound_dtor_id compound_dtor)
{
        VM_BUG_ON_PAGE(compound_dtor >= NR_COMPOUND_DTORS, page);
        page[1].compound_dtor = compound_dtor;
}

``````````````````````````````
./include/linux/mm.h

static inline compound_page_dtor *get_compound_page_dtor(struct page *page)
{
        VM_BUG_ON_PAGE(page[1].compound_dtor >= NR_COMPOUND_DTORS, page);
        return compound_page_dtors[page[1].compound_dtor];
}


``````````````````````````````

./mm/page_alloc.c:233


static void free_compound_page(struct page *page);
compound_page_dtor * const compound_page_dtors[] = {
        NULL,
        free_compound_page,
#ifdef CONFIG_HUGETLB_PAGE 
        free_huge_page,           <========== free_huge_page
#endif
};



``````````````````````````````

./mm/hugetlb.c:1254

static void prep_new_huge_page(struct hstate *h, struct page *page, int nid)
{
        INIT_LIST_HEAD(&page->lru);
        set_compound_page_dtor(page, HUGETLB_PAGE_DTOR);             <================== set_compound_page_dtor
        spin_lock(&hugetlb_lock);
        set_hugetlb_cgroup(page, NULL);
        h->nr_huge_pages++;
        h->nr_huge_pages_node[nid]++;
        spin_unlock(&hugetlb_lock);
        put_page(page); /* free it into the hugepage allocator */
}


``````````````````````````````

./mm/hugetlb.c:1578


/*
 * There are two ways to allocate a huge page:
 * 1. When you have a VMA and an address (like a fault)
 * 2. When you have no VMA (like when setting /proc/.../nr_hugepages)
 *
 * 'vma' and 'addr' are only for (1).  'nid' is always NUMA_NO_NODE in
 * this case which signifies that the allocation should be done with
 * respect for the VMA's memory policy.
 *
 * For (2), we ignore 'vma' and 'addr' and use 'nid' exclusively. This
 * implies that memory policies will not be taken in to account.
 */
static struct page *__alloc_buddy_huge_page(struct hstate *h,
                struct vm_area_struct *vma, unsigned long addr, int nid)
{
        struct page *page;
        unsigned int r_nid;

        if (hstate_is_gigantic(h))
                return NULL;

        /*
         * Make sure that anyone specifying 'nid' is not also specifying a VMA.
         * This makes sure the caller is picking _one_ of the modes with which
         * we can call this function, not both.
         */
        if (vma || (addr != -1)) {
                VM_WARN_ON_ONCE(addr == -1);
                VM_WARN_ON_ONCE(nid != NUMA_NO_NODE);
        }
        /*
         * Assume we will successfully allocate the surplus page to
         * prevent racing processes from causing the surplus to exceed
         * overcommit
         *
         * This however introduces a different race, where a process B
         * tries to grow the static hugepage pool while alloc_pages() is
         * called by process A. B will only examine the per-node
         * counters in determining if surplus huge pages can be
         * converted to normal huge pages in adjust_pool_surplus(). A
         * won't be able to increment the per-node counter, until the
         * lock is dropped by B, but B doesn't drop hugetlb_lock until
         * no more huge pages can be converted from surplus to normal
         * state (and doesn't try to convert again). Thus, we have a
         * case where a surplus huge page exists, the pool is grown, and
         * the surplus huge page still exists after, even though it
         * should just have been converted to a normal huge page. This
         * does not leak memory, though, as the hugepage will be freed
         * once it is out of use. It also does not allow the counters to
         * go out of whack in adjust_pool_surplus() as we don't modify
         * the node values until we've gotten the hugepage and only the
         * per-node value is checked there.
         */
        spin_lock(&hugetlb_lock);
        if (h->surplus_huge_pages >= h->nr_overcommit_huge_pages) {
                spin_unlock(&hugetlb_lock);
                return NULL;
        } else {
                h->nr_huge_pages++;
                h->surplus_huge_pages++;
        }
        spin_unlock(&hugetlb_lock);

        page = __hugetlb_alloc_buddy_huge_page(h, vma, addr, nid);

        spin_lock(&hugetlb_lock);
        if (page) {
                INIT_LIST_HEAD(&page->lru);
                r_nid = page_to_nid(page);
                set_compound_page_dtor(page, HUGETLB_PAGE_DTOR);          <================== set_compound_page_dtor
                set_hugetlb_cgroup(page, NULL);
                /*
                 * We incremented the global counters already
                 */
                h->nr_huge_pages_node[r_nid]++;
                h->surplus_huge_pages_node[r_nid]++;
                __count_vm_event(HTLB_BUDDY_PGALLOC);
        } else {
                h->nr_huge_pages--;
                h->surplus_huge_pages--;
                __count_vm_event(HTLB_BUDDY_PGALLOC_FAIL);
        }
        spin_unlock(&hugetlb_lock);

        return page;
}



/\
||
____________________________________________________________________________________________________


./mm/swap.c:233

static void put_compound_page(struct page *page)
{
        struct page *page_head;

        /*
         * We see the PageCompound set and PageTail not set, so @page maybe:
         *  1. hugetlbfs head page, or
         *  2. THP head page.
         */
        if (likely(!PageTail(page))) {
                if (put_page_testzero(page)) {
                        /*
                         * By the time all refcounts have been released
                         * split_huge_page cannot run anymore from under us.
                         */
                        if (PageHead(page))
                                __put_compound_page(page);         <========
                        else
                                __put_single_page(page);
                }
                return;
        }

        /*
         * We see the PageCompound set and PageTail set, so @page maybe:
         *  1. a tail hugetlbfs page, or
         *  2. a tail THP page, or
         *  3. a split THP page.
         *
         *  Case 3 is possible, as we may race with
         *  __split_huge_page_refcount tearing down a THP page.
         */
        page_head = compound_head(page);
        if (!__compound_tail_refcounted(page_head))
                put_unrefcounted_compound_page(page_head, page);
        else
                put_refcounted_compound_page(page_head, page);
}



/\
||
____________________________________________________________________________________________________



---------------KERNEL-----------------
 0xffffffff811cced0 : free_huge_page+0x0/0x210 [kernel]
 0xffffffff81190b1b : __put_compound_page+0x2b/0x30 [kernel]
 0xffffffff81190b56 : put_compound_page+0x36/0x1a0 [kernel]
 0xffffffff81190cdd : put_page+0x1d/0x50 [kernel]
 0xffffffff812e7098 : remove_inode_hugepages+0x2a8/0x330 [kernel]
 0xffffffff812e713e : hugetlbfs_evict_inode+0x1e/0x40 [kernel]
 0xffffffff8121820e : evict+0xbe/0x1a0 [kernel]
 0xffffffff81218eab : iput+0x19b/0x200 [kernel]
 0xffffffff812147dc : __dentry_kill+0x17c/0x1e0 [kernel]
 0xffffffff812149e9 : dput+0x1a9/0x210 [kernel]
 0xffffffff811ffda8 : __fput+0x188/0x210 [kernel]
 0xffffffff811ffe6e : ____fput+0xe/0x10 [kernel]
 0xffffffff81099fc6 : task_work_run+0x86/0xb0 [kernel]
 0xffffffff81078806 : exit_to_usermode_loop+0x73/0xa2 [kernel]
 0xffffffff81003a6e : syscall_return_slowpath+0x4e/0x60 [kernel]
 0xffffffff817fa658 : int_ret_from_sys_call+0x25/0x8f [kernel]
free_huge_page



./mm/swap.c:272:

void put_page(struct page *page)
{
        if (unlikely(PageCompound(page)))
                put_compound_page(page);        <================ put_compound_page
        else if (put_page_testzero(page))
                __put_single_page(page);
}
EXPORT_SYMBOL(put_page);




/\
||
____________________________________________________________________________________________________


./fs/hugetlbfs/inode.c

static void huge_pagevec_release(struct pagevec *pvec)
{
        int i;

        for (i = 0; i < pagevec_count(pvec); ++i)
                put_page(pvec->pages[i]);           <=============== put_page

        pagevec_reinit(pvec);
}


/\
||
____________________________________________________________________________________________________


./fs/hugetlbfs/inode.c:349

/*
 * remove_inode_hugepages handles two distinct cases: truncation and hole
 * punch.  There are subtle differences in operation for each case.

 * truncation is indicated by end of range being LLONG_MAX
 *      In this case, we first scan the range and release found pages.
 *      After releasing pages, hugetlb_unreserve_pages cleans up region/reserv
 *      maps and global counts.  Page faults can not race with truncation
 *      in this routine.  hugetlb_no_page() prevents page faults in the
 *      truncated range.  It checks i_size before allocation, and again after
 *      with the page table lock for the page held.  The same lock must be
 *      acquired to unmap a page.
 * hole punch is indicated if end is not LLONG_MAX
 *      In the hole punch case we scan the range and release found pages.
 *      Only when releasing a page is the associated region/reserv map
 *      deleted.  The region/reserv map for ranges without associated
 *      pages are not modified.  Page faults can race with hole punch.
 *      This is indicated if we find a mapped page.
 * Note: If the passed end of range value is beyond the end of file, but
 * not LLONG_MAX this routine still performs a hole punch operation.
 */
static void remove_inode_hugepages(struct inode *inode, loff_t lstart,
                                   loff_t lend)
{
        struct hstate *h = hstate_inode(inode);
        struct address_space *mapping = &inode->i_data;
        const pgoff_t start = lstart >> huge_page_shift(h);
        const pgoff_t end = lend >> huge_page_shift(h);
        struct vm_area_struct pseudo_vma;
        struct pagevec pvec;
        pgoff_t next;
        int i, freed = 0;
        long lookup_nr = PAGEVEC_SIZE;
        bool truncate_op = (lend == LLONG_MAX);

        memset(&pseudo_vma, 0, sizeof(struct vm_area_struct));
        pseudo_vma.vm_flags = (VM_HUGETLB | VM_MAYSHARE | VM_SHARED);
        pagevec_init(&pvec, 0);
        next = start;
        while (next < end) {
                /*
                 * Don't grab more pages than the number left in the range.
                 */
                if (end - next < lookup_nr)
                        lookup_nr = end - next;

                /*
                 * When no more pages are found, we are done.
                 */
                if (!pagevec_lookup(&pvec, mapping, next, lookup_nr))
                        break;

                for (i = 0; i < pagevec_count(&pvec); ++i) {
                        struct page *page = pvec.pages[i];
                        u32 hash;

                        /*
                         * The page (index) could be beyond end.  This is
                         * only possible in the punch hole case as end is
                         * max page offset in the truncate case.
                         */
                        next = page->index;
                        if (next >= end)
                                break;

                        hash = hugetlb_fault_mutex_hash(h, current->mm,
                                                        &pseudo_vma,
                                                        mapping, next, 0);
                        mutex_lock(&hugetlb_fault_mutex_table[hash]);

                        lock_page(page);
                        if (likely(!page_mapped(page))) {
                                bool rsv_on_error = !PagePrivate(page);
                                /*
                                 * We must free the huge page and remove
                                 * from page cache (remove_huge_page) BEFORE
                                 * removing the region/reserve map
                                 * (hugetlb_unreserve_pages).  In rare out
                                 * of memory conditions, removal of the
                                 * region/reserve map could fail.  Before
                                 * free'ing the page, note PagePrivate which
                                 * is used in case of error.
                                 */
                                remove_huge_page(page);
                                freed++;
                                if (!truncate_op) {
                                        if (unlikely(hugetlb_unreserve_pages(
                                                        inode, next,
                                                        next + 1, 1)))
                                                hugetlb_fix_reserve_counts(
                                                        inode, rsv_on_error);
                                }
                        } else {
                                /*
                                 * If page is mapped, it was faulted in after
                                 * being unmapped.  It indicates a race between
                                 * hole punch and page fault.  Do nothing in
                                 * this case.  Getting here in a truncate
                                 * operation is a bug.
                                 */
                                BUG_ON(truncate_op);
                        }

                        unlock_page(page);
                        mutex_unlock(&hugetlb_fault_mutex_table[hash]);
                }
                ++next;
                huge_pagevec_release(&pvec);          <============ calls "put_page" through huge_pagevec_release
                cond_resched();
        }

        if (truncate_op)
                (void)hugetlb_unreserve_pages(inode, start, LONG_MAX, freed);
}


/\
||
____________________________________________________________________________________________________


./fs/hugetlbfs/inode.c:443

static void hugetlbfs_evict_inode(struct inode *inode)
{
        struct resv_map *resv_map;

        remove_inode_hugepages(inode, 0, LLONG_MAX);                   <============ remove_inode_hugepages
        resv_map = (struct resv_map *)inode->i_mapping->private_data;
        /* root inode doesn't have the resv_map, so we should check it */
        if (resv_map)
                resv_map_release(&resv_map->refs);
        clear_inode(inode);
}


/\
||
____________________________________________________________________________________________________



./fs/hugetlbfs/inode.c

static const struct super_operations hugetlbfs_ops = {
        .alloc_inode    = hugetlbfs_alloc_inode,
        .destroy_inode  = hugetlbfs_destroy_inode,
        .evict_inode    = hugetlbfs_evict_inode,         <========
        .statfs         = hugetlbfs_statfs,
        .put_super      = hugetlbfs_put_super,
        .show_options   = generic_show_options,
};


/\
||
____________________________________________________________________________________________________



./fs/inode.c:521

/*
 * Free the inode passed in, removing it from the lists it is still connected
 * to. We remove any pages still attached to the inode and wait for any IO that
 * is still in progress before finally destroying the inode.
 *
 * An inode must already be marked I_FREEING so that we avoid the inode being
 * moved back onto lists if we race with other code that manipulates the lists
 * (e.g. writeback_single_inode). The caller is responsible for setting this.
 *
 * An inode must already be removed from the LRU list before being evicted from
 * the cache. This should occur atomically with setting the I_FREEING state
 * flag, so no inodes here should ever be on the LRU when being evicted.
 */
static void evict(struct inode *inode)
{
        const struct super_operations *op = inode->i_sb->s_op;

        BUG_ON(!(inode->i_state & I_FREEING));
        BUG_ON(!list_empty(&inode->i_lru));

        if (!list_empty(&inode->i_io_list))
                inode_io_list_del(inode);

        inode_sb_list_del(inode);

        /*
         * Wait for flusher thread to be done with the inode so that filesystem
         * does not start destroying it while writeback is still running. Since
         * the inode has I_FREEING set, flusher thread won't start new work on
         * the inode.  We just have to wait for running writeback to finish.
         */
        inode_wait_for_writeback(inode);

        if (op->evict_inode) {                 
                op->evict_inode(inode);  <=============== calls "hugetlbfs_evict_inode"
        } else {
                truncate_inode_pages_final(&inode->i_data);
                clear_inode(inode);
        }
        if (S_ISBLK(inode->i_mode) && inode->i_bdev)
                bd_forget(inode);
        if (S_ISCHR(inode->i_mode) && inode->i_cdev)
                cd_forget(inode);

        remove_inode_hash(inode);

        spin_lock(&inode->i_lock);
        wake_up_bit(&inode->i_state, __I_NEW);
        BUG_ON(inode->i_state != (I_FREEING | I_CLEAR));
        spin_unlock(&inode->i_lock);

        destroy_inode(inode);
}


/\
||
____________________________________________________________________________________________________

/*
 * Called when we're dropping the last reference
 * to an inode.
 *
 * Call the FS "drop_inode()" function, defaulting to
 * the legacy UNIX filesystem behaviour.  If it tells
 * us to evict inode, do so.  Otherwise, retain inode
 * in cache if fs is alive, sync and evict if fs is
 * shutting down.
 */
static void iput_final(struct inode *inode)
{
        struct super_block *sb = inode->i_sb;
        const struct super_operations *op = inode->i_sb->s_op;
        int drop;

        WARN_ON(inode->i_state & I_NEW);

        if (op->drop_inode)
                drop = op->drop_inode(inode);
        else
                drop = generic_drop_inode(inode);

        if (!drop && (sb->s_flags & MS_ACTIVE)) {
                inode->i_state |= I_REFERENCED;
                inode_add_lru(inode);
                spin_unlock(&inode->i_lock);
                return;
        }

        if (!drop) {
                inode->i_state |= I_WILL_FREE;
                spin_unlock(&inode->i_lock);
                write_inode_now(inode, 1);
                spin_lock(&inode->i_lock);
                WARN_ON(inode->i_state & I_NEW);
                inode->i_state &= ~I_WILL_FREE;
        }

        inode->i_state |= I_FREEING;
        if (!list_empty(&inode->i_lru))
                inode_lru_list_del(inode);
        spin_unlock(&inode->i_lock);

        evict(inode);            <================= evict
}


/\
||
____________________________________________________________________________________________________


./fs/inode.c:1489

/**
 *      iput    - put an inode
 *      @inode: inode to put
 *
 *      Puts an inode, dropping its usage count. If the inode use count hits
 *      zero, the inode is then freed and may also be destroyed.
 *
 *      Consequently, iput() can sleep.
 */
void iput(struct inode *inode)
{
        if (!inode)
                return;
        BUG_ON(inode->i_state & I_CLEAR);
retry:
        if (atomic_dec_and_lock(&inode->i_count, &inode->i_lock)) {
                if (inode->i_nlink && (inode->i_state & I_DIRTY_TIME)) {
                        atomic_inc(&inode->i_count);
                        inode->i_state &= ~I_DIRTY_TIME;
                        spin_unlock(&inode->i_lock);
                        trace_writeback_lazytime_iput(inode);
                        mark_inode_dirty_sync(inode);
                        goto retry;
                }
                iput_final(inode);            <=========== calls "evict" through iput_final
        }
}
EXPORT_SYMBOL(iput);


/\
||
____________________________________________________________________________________________________


./fs/dcache.c:357:static void dentry_iput(struct dentry * dentry)

/*
 * Release the dentry's inode, using the filesystem
 * d_iput() operation if defined. Dentry has no refcount
 * and is unhashed.
 */
static void dentry_iput(struct dentry * dentry)
        __releases(dentry->d_lock)
        __releases(dentry->d_inode->i_lock)
{
        struct inode *inode = dentry->d_inode;
        if (inode) {
                __d_clear_type_and_inode(dentry);
                hlist_del_init(&dentry->d_u.d_alias);
                spin_unlock(&dentry->d_lock);
                spin_unlock(&inode->i_lock);
                if (!inode->i_nlink)
                        fsnotify_inoderemove(inode);
                if (dentry->d_op && dentry->d_op->d_iput)
                        dentry->d_op->d_iput(dentry, inode);
                else
                        iput(inode);                        <============= iput
        } else {
                spin_unlock(&dentry->d_lock);
        }
}


/\
||
____________________________________________________________________________________________________



./fs/dcache.c:526

static void __dentry_kill(struct dentry *dentry)
{
        struct dentry *parent = NULL;
        bool can_free = true;
        if (!IS_ROOT(dentry))
                parent = dentry->d_parent;

        /*
         * The dentry is now unrecoverably dead to the world.
         */
        lockref_mark_dead(&dentry->d_lockref);

        /*
         * inform the fs via d_prune that this dentry is about to be
         * unhashed and destroyed.
         */
        if (dentry->d_flags & DCACHE_OP_PRUNE)
                dentry->d_op->d_prune(dentry);

        if (dentry->d_flags & DCACHE_LRU_LIST) {
                if (!(dentry->d_flags & DCACHE_SHRINK_LIST))
                        d_lru_del(dentry);
        }
        /* if it was on the hash then remove it */
        __d_drop(dentry);
        __list_del_entry(&dentry->d_child);
        /*
         * Inform d_walk() that we are no longer attached to the
         * dentry tree
         */
        dentry->d_flags |= DCACHE_DENTRY_KILLED;
        if (parent)
                spin_unlock(&parent->d_lock);
        dentry_iput(dentry);                        <============= calls "iput" through dentry_iput
        /*
         * dentry_iput drops the locks, at which point nobody (except
         * transient RCU lookups) can reach this dentry.
         */
        BUG_ON(dentry->d_lockref.count > 0);
        this_cpu_dec(nr_dentry);
        if (dentry->d_op && dentry->d_op->d_release)
                dentry->d_op->d_release(dentry);

        spin_lock(&dentry->d_lock);
        if (dentry->d_flags & DCACHE_SHRINK_LIST) {
                dentry->d_flags |= DCACHE_MAY_FREE;
                can_free = false;
        }
        spin_unlock(&dentry->d_lock);
        if (likely(can_free))
                dentry_free(dentry);
}


/\
||
____________________________________________________________________________________________________


./fs/dcache.c:585


/*
 * Finish off a dentry we've decided to kill.
 * dentry->d_lock must be held, returns with it unlocked.
 * If ref is non-zero, then decrement the refcount too.
 * Returns dentry requiring refcount drop, or NULL if we're done.
 */
static struct dentry *dentry_kill(struct dentry *dentry)
        __releases(dentry->d_lock)
{
        struct inode *inode = dentry->d_inode;
        struct dentry *parent = NULL;

        if (inode && unlikely(!spin_trylock(&inode->i_lock)))
                goto failed;

        if (!IS_ROOT(dentry)) {
                parent = dentry->d_parent;
                if (unlikely(!spin_trylock(&parent->d_lock))) {
                        if (inode)
                                spin_unlock(&inode->i_lock);
                        goto failed;
                }
        }

        __dentry_kill(dentry);               <=========== __dentry_kill
        return parent;

failed:
        spin_unlock(&dentry->d_lock);
        return dentry; /* try again with same dentry */
}



/\
||
____________________________________________________________________________________________________




./fs/dcache.c:775

 *
 * Release a dentry. This will drop the usage count and if appropriate
 * call the dentry unlink method as well as removing it from the queues and
 * releasing its resources. If the parent dentries were scheduled for release
 * they too may now get deleted.
 */
void dput(struct dentry *dentry)
{
        if (unlikely(!dentry))
                return;

repeat:
        might_sleep();

        rcu_read_lock();
        if (likely(fast_dput(dentry))) {
                rcu_read_unlock();
                return;
        }

        /* Slow case: now with the dentry lock held */
        rcu_read_unlock();

        /* Unreachable? Get rid of it */
        if (unlikely(d_unhashed(dentry)))
                goto kill_it;

        if (unlikely(dentry->d_flags & DCACHE_DISCONNECTED))
                goto kill_it;

        if (unlikely(dentry->d_flags & DCACHE_OP_DELETE)) {
                if (dentry->d_op->d_delete(dentry))
                        goto kill_it;
        }

        if (!(dentry->d_flags & DCACHE_REFERENCED))
                dentry->d_flags |= DCACHE_REFERENCED;
        dentry_lru_add(dentry);

        dentry->d_lockref.count--;
        spin_unlock(&dentry->d_lock);
        return;

kill_it:
        dentry = dentry_kill(dentry);   <=========== calls "__dentry_kill"  through dentry_kill
        if (dentry) {
                cond_resched();
                goto repeat;
        }
}
EXPORT_SYMBOL(dput);


/\
||
____________________________________________________________________________________________________


./fs/file_table.c:187

/* the real guts of fput() - releasing the last reference to file
 */
static void __fput(struct file *file)
{
        struct dentry *dentry = file->f_path.dentry;
        struct vfsmount *mnt = file->f_path.mnt;
        struct inode *inode = file->f_inode;

        might_sleep();

        fsnotify_close(file);
        /*
         * The function eventpoll_release() should be the first called
         * in the file cleanup chain.
         */
        eventpoll_release(file);
        locks_remove_file(file);

        if (unlikely(file->f_flags & FASYNC)) {
                if (file->f_op->fasync)
                        file->f_op->fasync(-1, file, 0);
        }
        ima_file_free(file);
        if (file->f_op->release)
                file->f_op->release(inode, file);
        security_file_free(file);
        if (unlikely(S_ISCHR(inode->i_mode) && inode->i_cdev != NULL &&
                     !(file->f_mode & FMODE_PATH))) {
                cdev_put(inode->i_cdev);
        }
        fops_put(file->f_op);
        put_pid(file->f_owner.pid);
        if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
                i_readcount_dec(inode);
        if (file->f_mode & FMODE_WRITER) {
                put_write_access(inode);
                __mnt_drop_write(mnt);
        }
        file->f_path.dentry = NULL;
        file->f_path.mnt = NULL;
        file->f_inode = NULL;
        file_free(file);
        dput(dentry);           <=========== dput
        mntput(mnt);
}



/\
||
____________________________________________________________________________________________________



./fs/file_table.c:243

static void ____fput(struct callback_head *work)
{
        __fput(container_of(work, struct file, f_u.fu_rcuhead));        <============== __fput
}




/\
||
____________________________________________________________________________________________________





./kernel/task_work.c:13: * Queue @work for task_work_run() below and notify the @task if @notify.
./kernel/task_work.c:64:	 * we raced with task_work_run(), *pprev == NULL/exited.
./kernel/task_work.c:80: * task_work_run - execute the works added by task_work_add()
./kernel/task_work.c:85: * new work after task_work_run() returns.
./kernel/task_work.c:87:void task_work_run(void)
./kernel/signal.c:1925:		task_work_run();
./kernel/signal.c:2145:		task_work_run();
./include/linux/task_work.h:17:void task_work_run(void);
./include/linux/task_work.h:21:	task_work_run();
./include/linux/tracehook.h:191:		task_work_run();






./kernel/task_work.c:87

/**
 * task_work_run - execute the works added by task_work_add()
 *
 * Flush the pending works. Should be used by the core kernel code.
 * Called before the task returns to the user-mode or stops, or when
 * it exits. In the latter case task_work_add() can no longer add the
 * new work after task_work_run() returns.
 */
void task_work_run(void)
{
        struct task_struct *task = current;
        struct callback_head *work, *head, *next;

        for (;;) {
                /*
                 * work->func() can do task_work_add(), do not set
                 * work_exited unless the list is empty.
                 */
                do {
                        work = ACCESS_ONCE(task->task_works);
                        head = !work && (task->flags & PF_EXITING) ?
                                &work_exited : NULL;
                } while (cmpxchg(&task->task_works, work, head) != work);

                if (!work)
                        break;
                /*
                 * Synchronize with task_work_cancel(). It can't remove
                 * the first entry == work, cmpxchg(task_works) should
                 * fail, but it can play with *work and other entries.
                 */
                raw_spin_unlock_wait(&task->pi_lock);
                smp_mb();

                do {
                        next = work->next;
                        work->func(work);
                        work = next;
                        cond_resched();
                } while (work);
        }
}



/\
||
____________________________________________________________________________________________________



./arch/x86/entry/common.c:226

static void exit_to_usermode_loop(struct pt_regs *regs, u32 cached_flags)
{
        /*
         * In order to return to user mode, we need to have IRQs off with
         * none of _TIF_SIGPENDING, _TIF_NOTIFY_RESUME, _TIF_USER_RETURN_NOTIFY,
         * _TIF_UPROBE, or _TIF_NEED_RESCHED set.  Several of these flags
         * can be set at any time on preemptable kernels if we have IRQs on,
         * so we need to loop.  Disabling preemption wouldn't help: doing the
         * work to clear some of the flags can sleep.
         */
        while (true) {
                /* We have work to do. */
                local_irq_enable();

                if (cached_flags & _TIF_NEED_RESCHED)
                        schedule();

                if (cached_flags & _TIF_UPROBE)
                        uprobe_notify_resume(regs);

                /* deal with pending signal delivery */
                if (cached_flags & _TIF_SIGPENDING)
                        do_signal(regs);

                if (cached_flags & _TIF_NOTIFY_RESUME) {
                        clear_thread_flag(TIF_NOTIFY_RESUME);
                        tracehook_notify_resume(regs);
                }

                if (cached_flags & _TIF_USER_RETURN_NOTIFY)
                        fire_user_return_notifiers();

                /* Disable IRQs and retry */
                local_irq_disable();

                cached_flags = READ_ONCE(pt_regs_to_thread_info(regs)->flags);

                if (!(cached_flags & EXIT_TO_USERMODE_LOOP_FLAGS))
                        break;

        }
}


/\
||
____________________________________________________________________________________________________



./arch/x86/entry/common.c:

/* Called with IRQs disabled. */
__visible inline void prepare_exit_to_usermode(struct pt_regs *regs)
{
        struct thread_info *ti = pt_regs_to_thread_info(regs);
        u32 cached_flags;

        if (IS_ENABLED(CONFIG_PROVE_LOCKING) && WARN_ON(!irqs_disabled()))
                local_irq_disable();

        lockdep_sys_exit();

        cached_flags = READ_ONCE(ti->flags);

        if (unlikely(cached_flags & EXIT_TO_USERMODE_LOOP_FLAGS))
                exit_to_usermode_loop(regs, cached_flags);              <============== exit_to_usermode_loop

#ifdef CONFIG_COMPAT
        /*
         * Compat syscalls set TS_COMPAT.  Make sure we clear it before
         * returning to user mode.  We need to clear it *after* signal
         * handling, because syscall restart has a fixup for compat
         * syscalls.  The fixup is exercised by the ptrace_syscall_32
         * selftest.
         */
        ti->status &= ~TS_COMPAT;
#endif

        user_enter();
}



/\
||
____________________________________________________________________________________________________



./arch/x86/entry/common.c:329



/*
 * Called with IRQs on and fully valid regs.  Returns with IRQs off in a
 * state such that we can immediately switch to user mode.
 */
__visible inline void syscall_return_slowpath(struct pt_regs *regs)
{
        struct thread_info *ti = pt_regs_to_thread_info(regs);
        u32 cached_flags = READ_ONCE(ti->flags);

        CT_WARN_ON(ct_state() != CONTEXT_KERNEL);

        if (IS_ENABLED(CONFIG_PROVE_LOCKING) &&
            WARN(irqs_disabled(), "syscall %ld left IRQs disabled", regs->orig_ax))
                local_irq_enable();

        /*
         * First do one-time work.  If these work items are enabled, we
         * want to run them exactly once per syscall exit with IRQs on.
         */
        if (unlikely(cached_flags & SYSCALL_EXIT_WORK_FLAGS))
                syscall_slow_exit_work(regs, cached_flags);

        local_irq_disable();
        prepare_exit_to_usermode(regs);                 <============== invokes:  exit_to_usermode_loop                 
}


/\
||
____________________________________________________________________________________________________



./arch/x86/entry/entry_64.S:317:GLOBAL(int_ret_from_sys_call)

/*
 * Syscall return path ending with IRET.
 * Has correct iret frame.
 */
GLOBAL(int_ret_from_sys_call)
        movq    %rsp, %rdi
        call    syscall_return_slowpath /* returns with IRQs disabled */      <========= syscall_return_slowpath
        TRACE_IRQS_IRETQ                /* we're about to change IF */

        /*
         * Try to use SYSRET instead of IRET if we're returning to
         * a completely clean 64-bit userspace context.
         */
        movq    RCX(%rsp), %rcx
        movq    RIP(%rsp), %r11
        cmpq    %rcx, %r11                      /* RCX == RIP */
        jne     opportunistic_sysret_failed

        /*
         * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
         * in kernel space.  This essentially lets the user take over
         * the kernel, since userspace controls RSP.
         *
         * If width of "canonical tail" ever becomes variable, this will need
         * to be updated to remain correct on both old and new CPUs.
         */
        .ifne __VIRTUAL_MASK_SHIFT - 47
        .error "virtual address width changed -- SYSRET checks need update"
        .endif

        /* Change top 16 bits to be the sign-extension of 47th bit */
        shl     $(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
        sar     $(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx

        /* If this changed %rcx, it was not canonical */
        cmpq    %rcx, %r11
        jne     opportunistic_sysret_failed

        cmpq    $__USER_CS, CS(%rsp)            /* CS must match SYSRET */
        jne     opportunistic_sysret_failed

        movq    R11(%rsp), %r11
        cmpq    %r11, EFLAGS(%rsp)              /* R11 == RFLAGS */
        jne     opportunistic_sysret_failed

        /*
         * SYSRET can't restore RF.  SYSRET can restore TF, but unlike IRET,
         * restoring TF results in a trap from userspace immediately after
         * SYSRET.  This would cause an infinite loop whenever #DB happens
         * with register state that satisfies the opportunistic SYSRET
         * conditions.  For example, single-stepping this user code:
         *
         *           movq       $stuck_here, %rcx
         *           pushfq
         *           popq %r11
         *   stuck_here:
         *
         * would never get past 'stuck_here'.
         */
        testq   $(X86_EFLAGS_RF|X86_EFLAGS_TF), %r11
        jnz     opportunistic_sysret_failed

        /* nothing to check for RSP */

        cmpq    $__USER_DS, SS(%rsp)            /* SS must match SYSRET */
        jne     opportunistic_sysret_failed

        /*
         * We win! This label is here just for ease of understanding
         * perf profiles. Nothing jumps here.
         */




#########################################################################################################

