
================ENTRY=======================================================
dequeue_huge_page_node
1519960386578:qemu-system-x86(188689)[init(1)]
page 0xffffea007e000000 _count 1 flags 17fff8000004000 mapping 0x0 _mapcount -1
----------------USER------------------
 0x563b78574f66 : os_mem_prealloc+0xf6/0x1a0 [/usr/bin/qemu-system-x86_64]
 0x563b7836a577 : tpm_backend_thread_end+0x6d7/0xdb0 [/usr/bin/qemu-system-x86_64]
 0x563b7835265e : object_add+0x16e/0x210 [/usr/bin/qemu-system-x86_64]
 0x563b7833f1e4 : dma_acct_start+0xcb4/0x2030 [/usr/bin/qemu-system-x86_64]
 0x563b7858454a : qemu_opts_foreach+0x6a/0xc0 [/usr/bin/qemu-system-x86_64]
 0x563b7820d2cb : main+0xcbb/0x81c8 [/usr/bin/qemu-system-x86_64]
 0x7f6c3fb27f45 : __libc_start_main+0xf5/0x1e0 [/lib/x86_64-linux-gnu/libc-2.19.so]
 0x563b78214801 : _start+0x29/0x1db8 [/usr/bin/qemu-system-x86_64]

---------------KERNEL-----------------
Returning from:  0xffffffff811cb8f0 : dequeue_huge_page_node+0x0/0xe0 [kernel]
Returning to  :  0xffffffff811ce68f : alloc_huge_page+0x29f/0x3f0 [kernel]
 0xffffffff811d0838 : hugetlb_fault+0x2e8/0x7d0 [kernel]
 0xffffffff811b3786 : handle_mm_fault+0x486/0x540 [kernel]
 0xffffffff81067c0a : __do_page_fault+0x19a/0x430 [kernel]
 0xffffffff81067ec2 : do_page_fault+0x22/0x30 [kernel]
 0xffffffff817fc678 : page_fault+0x28/0x30 [kernel]
dequeue_huge_page_node
================EXIT========================================================






================ENTRY=======================================================
free_huge_page
1519961627178:vhost_thread1(188271)[monitor(188268)]
page 0xffffea007e000000 _count 0 flags 17fff8000004004 mapping 0x0 _mapcount -1
----------------USER------------------
 0x7ff7fb5f740d : __close_nocancel+0x24/0x57 [/lib/x86_64-linux-gnu/libpthread-2.19.so]
 0x55fff1 : user_destroy_device+0x141/0x170 [/usr/sbin/ovs-vswitchd]
 0x5517a0 : vserver_message_handler+0x1a0/0x550 [/usr/sbin/ovs-vswitchd]

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
================EXIT========================================================





================ENTRY=======================================================
dequeue_huge_page_node
1519960386578:qemu-system-x86(188689)[init(1)]
page 0xffffea007e000000 _count 1 flags 17fff8000004000 mapping 0x0 _mapcount -1
----------------USER------------------
 0x563b78574f66 : os_mem_prealloc+0xf6/0x1a0 [/usr/bin/qemu-system-x86_64]
 0x563b7836a577 : tpm_backend_thread_end+0x6d7/0xdb0 [/usr/bin/qemu-system-x86_64]
 0x563b7835265e : object_add+0x16e/0x210 [/usr/bin/qemu-system-x86_64]
 0x563b7833f1e4 : dma_acct_start+0xcb4/0x2030 [/usr/bin/qemu-system-x86_64]
 0x563b7858454a : qemu_opts_foreach+0x6a/0xc0 [/usr/bin/qemu-system-x86_64]
 0x563b7820d2cb : main+0xcbb/0x81c8 [/usr/bin/qemu-system-x86_64]
 0x7f6c3fb27f45 : __libc_start_main+0xf5/0x1e0 [/lib/x86_64-linux-gnu/libc-2.19.so]
 0x563b78214801 : _start+0x29/0x1db8 [/usr/bin/qemu-system-x86_64]

---------------KERNEL-----------------
Returning from:  0xffffffff811cb8f0 : dequeue_huge_page_node+0x0/0xe0 [kernel]
Returning to  :  0xffffffff811ce68f : alloc_huge_page+0x29f/0x3f0 [kernel]
 0xffffffff811d0838 : hugetlb_fault+0x2e8/0x7d0 [kernel]
 0xffffffff811b3786 : handle_mm_fault+0x486/0x540 [kernel]
 0xffffffff81067c0a : __do_page_fault+0x19a/0x430 [kernel]
 0xffffffff81067ec2 : do_page_fault+0x22/0x30 [kernel]
 0xffffffff817fc678 : page_fault+0x28/0x30 [kernel]
dequeue_huge_page_node
================EXIT========================================================



###################################################################################################





The closest OVS and DPDK upstream versions in Ericssons OVS and DPDK is the following: 

DPDK version 2.2, last upstream commit seen from Ericsson DPDK is: 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
commit a38e5ec15e3fe615b94f3cc5edca5974dab325ab 
Author: Thomas Monjalon <thomas.monjalon@6wind.com> 
Date: Tue Dec 15 17:42:32 2015 +0100 

version: 2.2.0 

Signed-off-by: Thomas Monjalon <thomas.monjalon@6wind.com> 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 


Openvswitch version 2.5.1, last upstream commit seen from Ericsson Openvswitch is: 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
commit 92a623b9457f254df74fb219c9982e312603fbd7 
Author: Jesse Gross <jesse@kernel.org> 
Date: Thu Aug 18 15:45:25 2016 -0700 

match: Only print external tunnel flags. 

changelog update for branch-2.5 uplift 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 






###################################################################################################

cat Ericsson_OVS_post_migration/daemon.log_processed | grep "VHOST_CONFIG" 

 VHOST_CONFIG: read message VHOST_USER_SET_VRING_ENABLE, 2
 VHOST_CONFIG: set queue enable: 1 to qp idx: 1
 VHOST_CONFIG: read message VHOST_USER_SET_VRING_ADDR, 0
 VHOST_CONFIG: read message VHOST_USER_SET_FEATURES, 1
 VHOST_CONFIG: read message VHOST_USER_SET_FEATURES, 2



 VHOST_CONFIG: read message VHOST_USER_SET_VRING_KICK, 0
 VHOST_CONFIG: vring kick idx:1 file:249
 VHOST_CONFIG: virtio is now ready for processing.

 VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
 VHOST_CONFIG: vring call idx:1 file:256

 VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
 VHOST_CONFIG: vring base idx:0 file:0

 VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
 VHOST_CONFIG: vring base idx:1 file:0


 VHOST_CONFIG: recvmsg failed
 VHOST_CONFIG: vhost peer closed 0


=====================================================================================================
CHECK VIRTIO IS READY

 VHOST_CONFIG: read message VHOST_USER_SET_VRING_KICK, 0
 VHOST_CONFIG: vring kick idx:1 file:249
 VHOST_CONFIG: virtio is now ready for processing.

./lib/librte_vhost/vhost_user/vhost-net-user.c:416


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
        ret = read_vhost_message(connfd, &msg);              --------------->    read_vhost_message   
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
                user_destroy_device(ctx);        --------------->    user_destroy_device
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",       ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                vhost_message_str[msg.request]);                               VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
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

        case VHOST_USER_GET_VRING_BASE:                          ------------>  VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);          -------------> user_set_vring_kick
                break;
        case VHOST_USER_SET_VRING_CALL:                          ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
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


----------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/virtio-net-user.c:279

/*
 *  In vhost-user, when we receive kick message, will test whether virtio
 *  device is ready for packet processing.
 */
void
user_set_vring_kick(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct vhost_vring_file file;
        struct virtio_net *dev = get_device(ctx);

        file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
        if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
                file.fd = -1;
        else
                file.fd = pmsg->fds[0];
        RTE_LOG(INFO, VHOST_CONFIG,
                "vring kick idx:%d file:%d\n", file.index, file.fd);        =============>    VHOST_CONFIG: vring kick idx:1 file:249
        ops->set_vring_kick(ctx, &file);

        if (virtio_is_ready(dev) &&                    ----------> virtio_is_ready
                !(dev->flags & VIRTIO_DEV_RUNNING))
                        notify_ops->new_device(dev);
}

----------------------------------------------------------------------------------------------


./lib/librte_vhost/vhost_user/virtio-net-user.c:240

static int
virtio_is_ready(struct virtio_net *dev)
{
        struct vhost_virtqueue *rvq, *tvq;
        uint32_t i;

        for (i = 0; i < dev->virt_qp_nb; i++) {
                rvq = dev->virtqueue[i * VIRTIO_QNUM + VIRTIO_RXQ];
                tvq = dev->virtqueue[i * VIRTIO_QNUM + VIRTIO_TXQ];

                if (!vq_is_ready(rvq) || !vq_is_ready(tvq)) {
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "virtio is not ready for processing.\n");
                        return 0;
                }
        }

        RTE_LOG(INFO, VHOST_CONFIG,
                "virtio is now ready for processing.\n");        ==================>    VHOST_CONFIG: virtio is now ready for processing.
        return 1;
}



=====================================================================================================
READ VHOST MESSAGE

./lib/librte_vhost/vhost_user/vhost-net-user.c

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
        ret = read_vhost_message(connfd, &msg);              --------------->    read_vhost_message   
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
                user_destroy_device(ctx);
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
        case VHOST_USER_SET_VRING_CALL:                          ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
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


----------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:192

/* return bytes# of read on success or negative val on failure. */
static int
read_vhost_message(int sockfd, struct VhostUserMsg *msg)
{
        int ret;

        ret = read_fd_message(sockfd, (char *)msg, VHOST_USER_HDR_SIZE,    ------->  read_fd_message
                msg->fds, VHOST_MEMORY_MAX_NREGIONS);
        if (ret <= 0)
                return ret;

        if (msg && msg->size) {
                if (msg->size > sizeof(msg->payload)) {
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "invalid msg size: %d\n", msg->size);
                        return -1;
                }
                ret = read(sockfd, &msg->payload, msg->size);
                if (ret <= 0)
                        return ret;
                if (ret != (int)msg->size) {
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "read control message failed\n");
                        return -1;
                }
        }

        return ret;
}


------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c

/* return bytes# of read on success or negative val on failure. */
static int
read_fd_message(int sockfd, char *buf, int buflen, int *fds, int fd_num)
{
        struct iovec iov;
        struct msghdr msgh;
        size_t fdsize = fd_num * sizeof(int);
        char control[CMSG_SPACE(fdsize)];
        struct cmsghdr *cmsg;
        int ret;

        memset(&msgh, 0, sizeof(msgh));
        iov.iov_base = buf;
        iov.iov_len  = buflen;

        msgh.msg_iov = &iov;
        msgh.msg_iovlen = 1;
        msgh.msg_control = control;
        msgh.msg_controllen = sizeof(control);

        ret = recvmsg(sockfd, &msgh, 0);
        if (ret <= 0) {
                RTE_LOG(ERR, VHOST_CONFIG, "recvmsg failed\n");       ------------>   VHOST_CONFIG: recvmsg failed
                return ret;
        }

        if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
                RTE_LOG(ERR, VHOST_CONFIG, "truncted msg\n");
                return -1;
        }

        for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
                cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
                if ((cmsg->cmsg_level == SOL_SOCKET) &&
                        (cmsg->cmsg_type == SCM_RIGHTS)) {
                        memcpy(fds, CMSG_DATA(cmsg), fdsize);
                        break;
                }
        }

        return ret;
}

=====================================================================================================
SET VRING CALL

 VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
 VHOST_CONFIG: vring call idx:1 file:256


./lib/librte_vhost/vhost_user/vhost-net-user.c

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
                user_destroy_device(ctx);
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",       ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
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
        case VHOST_USER_SET_VRING_CALL:                          ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
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


------------------------------------------------------------------------------------------
ls  ./lib/librte_vhost/vhost_user

fd_man.c  
fd_man.h  
vhost-net-user.c  
vhost-net-user.h  
virtio-net-user.c  
virtio-net-user.h



./lib/librte_vhost/vhost_user/virtio-net-user.c:245

void
user_set_vring_call(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct vhost_vring_file file;

        file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
        if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
                file.fd = -1;
        else
                file.fd = pmsg->fds[0];
        RTE_LOG(INFO, VHOST_CONFIG,
                "vring call idx:%d file:%d\n", file.index, file.fd);
        ops->set_vring_call(ctx, &file);                      --------->   set_vring_call
}



------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:454


/**
 * Creates and initialise the vhost server.
 */
int
rte_vhost_driver_register(const char *path)
{
        struct vhost_server *vserver;

        pthread_mutex_lock(&g_vhost_server.server_mutex);
        if (ops == NULL)
                ops = get_virtio_net_callbacks();               --------->   ops

        if (g_vhost_server.vserver_cnt == MAX_VHOST_SERVER) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "error: the number of servers reaches maximum\n");
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver = calloc(sizeof(struct vhost_server), 1);
        if (vserver == NULL) {
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->listenfd = uds_socket(path);
        if (vserver->listenfd < 0) {
                free(vserver);
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->path = strdup(path);

        fdset_add(&g_vhost_server.fdset, vserver->listenfd,
                vserver_new_vq_conn, NULL, vserver);

        g_vhost_server.server[g_vhost_server.vserver_cnt++] = vserver;
        pthread_mutex_unlock(&g_vhost_server.server_mutex);

        return 0;
}

------------------------------------------------------------------------------------------
./lib/librte_vhost/virtio-net.c:852
/*
 * Called by main to setup callbacks when registering CUSE device.
 */
struct vhost_net_device_ops const *
get_virtio_net_callbacks(void)
{
        return &vhost_device_ops;        -------------->  vhost_device_ops
}


------------------------------------------------------------------------------------------

./lib/librte_vhost/virtio-net.c
/*
 * Function pointers are set for the device operations to allow CUSE to call
 * functions when an IOCTL, device_add or device_release is received.
 */
static const struct vhost_net_device_ops vhost_device_ops = {            <------------- vhost_device_ops
        .new_device = new_device,
        .destroy_device = destroy_device,

        .set_ifname = set_ifname,

        .get_features = get_features,
        .set_features = set_features,

        .set_vring_num = set_vring_num,
        .set_vring_addr = set_vring_addr,
        .set_vring_base = set_vring_base,
        .get_vring_base = get_vring_base,

        .set_vring_kick = set_vring_kick,
        .set_vring_call = set_vring_call,       <------------

        .set_backend = set_backend,

        .set_owner = set_owner,
        .reset_owner = reset_owner,
};


------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/virtio-net-user.c:245

void
user_set_vring_call(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct vhost_vring_file file;

        file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
        if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
                file.fd = -1;
        else
                file.fd = pmsg->fds[0];
        RTE_LOG(INFO, VHOST_CONFIG,
                "vring call idx:%d file:%d\n", file.index, file.fd);
        ops->set_vring_call(ctx, &file);                      --------->   set_vring_call
}


------------------------------------------------------------------------------------------

./lib/librte_vhost/virtio-net.c:727
/*
 * Called from CUSE IOCTL: VHOST_SET_VRING_CALL
 * The virtio device sends an eventfd to interrupt the guest. This fd gets
 * copied into our process space.
 */
static int
set_vring_call(struct vhost_device_ctx ctx, struct vhost_vring_file *file)
{
        struct virtio_net *dev;
        struct vhost_virtqueue *vq;
        uint32_t cur_qp_idx = file->index / VIRTIO_QNUM;

        dev = get_device(ctx);
        if (dev == NULL)
                return -1;

        /*
         * FIXME: VHOST_SET_VRING_CALL is the first per-vring message
         * we get, so we do vring queue pair allocation here.
         */
        if (cur_qp_idx + 1 > dev->virt_qp_nb) {
                if (alloc_vring_queue_pair(dev, cur_qp_idx) < 0)
                        return -1;
        }

        /* file->index refers to the queue index. The txq is 1, rxq is 0. */
        vq = dev->virtqueue[file->index];
        assert(vq != NULL);

        if (vq->callfd >= 0)
                close(vq->callfd);

        vq->callfd = file->fd;

        return 0;
}

------------------------------------------------------------------------------------------


./lib/librte_vhost/virtio-net.c:304


static int
alloc_vring_queue_pair(struct virtio_net *dev, uint32_t qp_idx)
{
        struct vhost_virtqueue *virtqueue = NULL;
        uint32_t virt_rx_q_idx = qp_idx * VIRTIO_QNUM + VIRTIO_RXQ;
        uint32_t virt_tx_q_idx = qp_idx * VIRTIO_QNUM + VIRTIO_TXQ;

        virtqueue = rte_malloc(NULL,
                               sizeof(struct vhost_virtqueue) * VIRTIO_QNUM, 0);
        if (virtqueue == NULL) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "Failed to allocate memory for virt qp:%d.\n", qp_idx);
                return -1;
        }

        dev->virtqueue[virt_rx_q_idx] = virtqueue;
        dev->virtqueue[virt_tx_q_idx] = virtqueue + VIRTIO_TXQ;

        init_vring_queue_pair(dev, qp_idx);

        dev->virt_qp_nb += 1;

        return 0;
}



===================================================================================

GET VRING BASE

 VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
 VHOST_CONFIG: vring base idx:0 file:0


./lib/librte_vhost/vhost_user/vhost-net-user.c


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
        ret = read_vhost_message(connfd, &msg);              --------------->    read_vhost_message   
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
                user_destroy_device(ctx);        --------------->    user_destroy_device
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",       ------------>   VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
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

        case VHOST_USER_GET_VRING_BASE:                          ------------>  VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
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

------------------------------------------------------------------------------------------

 VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
 VHOST_CONFIG: vring base idx:1 file:0

./lib/librte_vhost/vhost_user/virtio-net-user.c:288


/*
 * when virtio is stopped, qemu will send us the GET_VRING_BASE message.
 */
int
user_get_vring_base(struct vhost_device_ctx ctx,
        struct vhost_vring_state *state)
{
        struct virtio_net *dev = get_device(ctx);          ---------> get_device

        if (dev == NULL)
                return -1;
        /* We have to stop the queue (virtio) if it is running. */
        if (dev->flags & VIRTIO_DEV_RUNNING)
                notify_ops->destroy_device(dev);           ------------> destroy_device

        /* Here we are safe to get the last used index */
        ops->get_vring_base(ctx, state->index, state);         -----------> get_vring_base

        RTE_LOG(INFO, VHOST_CONFIG,
                "vring base idx:%d file:%d\n", state->index, state->num);
        /*
         * Based on current qemu vhost-user implementation, this message is
         * sent and only sent in vhost_vring_stop.
         * TODO: cleanup the vring, it isn't usable since here.
         */
        if (dev->virtqueue[state->index]->kickfd >= 0) {
                close(dev->virtqueue[state->index]->kickfd);
                dev->virtqueue[state->index]->kickfd = -1;
        }

        return 0;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/vhost-net-user.c:419:		user_set_vring_call(ctx, &msg);



/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{

        ret = read_vhost_message(connfd, &msg);


        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",
                vhost_message_str[msg.request]);
        switch (msg.request) {

        case VHOST_USER_SET_VRING_CALL:
                user_set_vring_call(ctx, &msg);
                break;


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


./lib/librte_vhost/vhost_user/virtio-net-user.c:256

void
user_set_vring_call(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct vhost_vring_file file;

        file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
        if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
                file.fd = -1;
        else
                file.fd = pmsg->fds[0];
        RTE_LOG(INFO, VHOST_CONFIG,
                "vring call idx:%d file:%d\n", file.index, file.fd);
        ops->set_vring_call(ctx, &file);
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/virtio-net.c:742


/*
 * Called from CUSE IOCTL: VHOST_SET_VRING_CALL
 * The virtio device sends an eventfd to interrupt the guest. This fd gets
 * copied into our process space.
 */
static int
set_vring_call(struct vhost_device_ctx ctx, struct vhost_vring_file *file)
{
        struct virtio_net *dev;
        struct vhost_virtqueue *vq;
        uint32_t cur_qp_idx = file->index / VIRTIO_QNUM;

        dev = get_device(ctx);
        if (dev == NULL)
                return -1;

        /*
         * FIXME: VHOST_SET_VRING_CALL is the first per-vring message
         * we get, so we do vring queue pair allocation here.
         */
        if (cur_qp_idx + 1 > dev->virt_qp_nb) {
                if (alloc_vring_queue_pair(dev, cur_qp_idx) < 0)          -------------->   alloc_vring_queue_pair
                        return -1;
        }

        /* file->index refers to the queue index. The txq is 1, rxq is 0. */
        vq = dev->virtqueue[file->index];
        assert(vq != NULL);

        if (vq->callfd >= 0)
                close(vq->callfd);

        vq->callfd = file->fd;

        return 0;
}


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/virtio-net.c

static int
alloc_vring_queue_pair(struct virtio_net *dev, uint32_t qp_idx)
{
        struct vhost_virtqueue *virtqueue = NULL;
        uint32_t virt_rx_q_idx = qp_idx * VIRTIO_QNUM + VIRTIO_RXQ;
        uint32_t virt_tx_q_idx = qp_idx * VIRTIO_QNUM + VIRTIO_TXQ;

        virtqueue = rte_malloc(NULL,
                               sizeof(struct vhost_virtqueue) * VIRTIO_QNUM, 0);
        if (virtqueue == NULL) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "Failed to allocate memory for virt qp:%d.\n", qp_idx);
                return -1;
        }

        dev->virtqueue[virt_rx_q_idx] = virtqueue;
        dev->virtqueue[virt_tx_q_idx] = virtqueue + VIRTIO_TXQ;

        init_vring_queue_pair(dev, qp_idx);

        dev->virt_qp_nb += 1;

        return 0;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/rte_virtio_net.h
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


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/**
 * Structure contains variables relevant to RX/TX virtqueues.
 */
struct vhost_virtqueue {
        struct vring_desc       *desc;                  /**< Virtqueue descriptor ring. */
        struct vring_avail      *avail;                 /**< Virtqueue available ring. */
        struct vring_used       *used;                  /**< Virtqueue used ring. */
        uint32_t                size;                   /**< Size of descriptor ring. */
        uint32_t                backend;                /**< Backend value to determine if device should started/stopped. */
        uint16_t                vhost_hlen;             /**< Vhost header length (varies depending on RX merge buffers. */
        volatile uint16_t       last_used_idx;          /**< Last index used on the available ring */
        volatile uint16_t       last_used_idx_res;      /**< Used for multiple devices reserving buffers. */
        int                     callfd;                 /**< Used to notify the guest (trigger interrupt). */
        int                     kickfd;                 /**< Currently unused as polling mode is enabled. */    ----------------> kickfd
        int                     enabled;
        uint64_t                reserved[16];           /**< Reserve some spaces for future extension. */
        struct buf_vector       buf_vec[BUF_VECTOR_MAX];        /**< for scatter RX. */
} __rte_cache_aligned;




~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

------------------------------------------------------------------------------------------

./lib/librte_vhost/virtio-net.c:134

/*
 * Searches the configuration core linked list and
 * retrieves the device if it exists.
 */
struct virtio_net *
get_device(struct vhost_device_ctx ctx)
{
        struct virtio_net_config_ll *ll_dev;

        ll_dev = get_config_ll_entry(ctx);

        if (ll_dev)
                return &ll_dev->dev;

        RTE_LOG(ERR, VHOST_CONFIG,
                "(%"PRIu64") Device not found in linked list.\n", ctx.fh);
        return NULL;
}



------------------------------------------------------------------------------------------

./lib/librte_vhost/virtio-net.c

/*
 * Function is called from the CUSE release function. This function will
 * cleanup the device and remove it from device configuration linked list.
 */
static void
destroy_device(struct vhost_device_ctx ctx)
{
        struct virtio_net_config_ll *ll_dev_cur_ctx, *ll_dev_last = NULL;
        struct virtio_net_config_ll *ll_dev_cur = ll_root;

        /* Find the linked list entry for the device to be removed. */
        ll_dev_cur_ctx = get_config_ll_entry(ctx);
        while (ll_dev_cur != NULL) {
                /*
                 * If the device is found or
                 * a device that doesn't exist is found then it is removed.
                 */
                if (ll_dev_cur == ll_dev_cur_ctx) {
                        /*
                         * If the device is running on a data core then call
                         * the function to remove it from the data core.
                         */
                        if ((ll_dev_cur->dev.flags & VIRTIO_DEV_RUNNING))
                                notify_ops->destroy_device(&(ll_dev_cur->dev));
                        ll_dev_cur = rm_config_ll_entry(ll_dev_cur,
                                        ll_dev_last);
                } else {
                        ll_dev_last = ll_dev_cur;
                        ll_dev_cur = ll_dev_cur->next;
                }
        }
}


------------------------------------------------------------------------------------------
./lib/librte_vhost/virtio-net.c:704

/*
 * Called from CUSE IOCTL: VHOST_GET_VRING_BASE
 * We send the virtio device our available ring last used index.
 */
static int
get_vring_base(struct vhost_device_ctx ctx, uint32_t index,
        struct vhost_vring_state *state)
{
        struct virtio_net *dev;

        dev = get_device(ctx);
        if (dev == NULL)
                return -1;

        state->index = index;
        /* State->index refers to the queue index. The txq is 1, rxq is 0. */
        state->num = dev->virtqueue[state->index]->last_used_idx;

        return 0;
}




===================================================================================

./lib/librte_vhost/rte_vhost_version.map:6


DPDK_2.0 {
        global:

        rte_vhost_dequeue_burst;
        rte_vhost_driver_callback_register;
        rte_vhost_driver_register;         <----------
        rte_vhost_driver_session_start;
        rte_vhost_enable_guest_notification;
        rte_vhost_enqueue_burst;
        rte_vhost_feature_disable;
        rte_vhost_feature_enable;
        rte_vhost_feature_get;

        local: *;
};

DPDK_2.1 {
        global:

        rte_vhost_driver_unregister;

} DPDK_2.0;



------------------------------------------------------------------------------------------

./doc/guides/prog_guide/vhost_lib.rst:46

*   Vhost driver registration

      rte_vhost_driver_register registers the vhost driver into the system.
      For vhost-cuse, character device file will be created under the /dev directory.
      Character device name is specified as the parameter.
      For vhost-user, a Unix domain socket server will be created with the parameter as the local socket path.  ===>   /var/run/openvswitch/vhue0fdfafa-c7 


------------------------------------------------------------------------------------------
http://dpdk.readthedocs.io/en/v16.04/sample_app_ug/vhost.html


For vhost cuse:

qemu-system-x86_64 ... \
-netdev tap,id=hostnet1,vhost=on,vhostfd=<open fd> \
-device virtio-net-pci, netdev=hostnet1,id=net1 \
-netdev tap,id=hostnet2,vhost=on,vhostfd=<open fd> \
-device virtio-net-pci, netdev=hostnet2,id=net1



For vhost user:

qemu-system-x86_64 ... \
-chardev socket,id=char1,path=<sock_path> \

-netdev type=vhost-user,id=hostnet1,chardev=char1 \
-device virtio-net-pci,netdev=hostnet1,id=net1 \

-chardev socket,id=char2,path=<sock_path> \        <=========== sock_path is the path for the socket file created by vhost.
-netdev type=vhost-user,id=hostnet2,chardev=char2 \

-device virtio-net-pci,netdev=hostnet2,id=net2



qemu-system-x86_64 -enable-kvm -name instance-00000522 -S -machine pc-i440fx-xenial,accel=kvm,usb=off -cpu host -m 32768 -realtime mlock=off -smp 8,sockets=4,cores=1,threads=2 -object memory-backend-file,id=ram-node0,prealloc=yes,mem-path=/mnt/huge_qemu_1G/libvirt/qemu,share=yes,size=34359738368,host-nodes=0,policy=bind -numa node,nodeid=0,cpus=0-7,memdev=ram-node0 -uuid bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3 -smbios type=1,manufacturer=OpenStack Foundation,product=OpenStack Nova,version=13.0.0,serial=4c4c4544-0042-4b10-8058-c8c04f5a4732,uuid=bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3,family=Virtual Machine -no-user-config -nodefaults -chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-instance-00000522/monitor.sock,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=discard -no-hpet -no-shutdown -boot strict=on -device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 -drive file=/var/lib/nova/instances/bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=directsync -device virtio-blk-pci,scsi=off,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 

-chardev socket,id=charnet0,path=/var/run/openvswitch/vhue0fdfafa-c7 
-netdev type=vhost-user,id=hostnet0,chardev=charnet0 
-device virtio-net-pci,netdev=hostnet0,id=net0,mac=fa:16:3e:08:c3:8d,bus=pci.0,addr=0x3 

-chardev file,id=charserial0,path=/var/lib/nova/instances/bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3/console.log -device isa-serial,chardev=charserial0,id=serial0 -chardev pty,id=charserial1 -device isa-serial,chardev=charserial1,id=serial1 -device usb-tablet,id=input0 -vnc 160.6.88.55:0 -k en-us -device cirrus-vga,id=video0,bus=pci.0,addr=0x2 -device i6300esb,id=watchdog0,


------------------------------------------------------------------------------------------



path = /var/run/openvswitch/vhue0fdfafa-c7   <===== For vhost-user, a Unix domain socket server will be created with the parameter as the local socket path.




./lib/librte_vhost/vhost_user/vhost-net-user.c:448

/**
 * Creates and initialise the vhost server.
 */
int
rte_vhost_driver_register(const char *path)
{
        struct vhost_server *vserver;

        pthread_mutex_lock(&g_vhost_server.server_mutex);
        if (ops == NULL)
                ops = get_virtio_net_callbacks();

        if (g_vhost_server.vserver_cnt == MAX_VHOST_SERVER) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "error: the number of servers reaches maximum\n");
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver = calloc(sizeof(struct vhost_server), 1);
        if (vserver == NULL) {
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->listenfd = uds_socket(path);
        if (vserver->listenfd < 0) {
                free(vserver);
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->path = strdup(path);

        fdset_add(&g_vhost_server.fdset, vserver->listenfd,
                vserver_new_vq_conn, NULL, vserver);               --------------------->  vserver_new_vq_conn

        g_vhost_server.server[g_vhost_server.vserver_cnt++] = vserver;
        pthread_mutex_unlock(&g_vhost_server.server_mutex);

        return 0;
}



https://linux.die.net/man/3/strdup
The strdup() function returns a pointer to a new string which is a duplicate of the string s.



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.c:142

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

        fdset_add_fd(pfdset, i, fd, rcb, wcb, dat);          fd - filedescriptor   rcb - read callback    wcb - writecallback
        pfdset->num++;

        pthread_mutex_unlock(&pfdset->fd_mutex);

        return 0;
}


~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.c

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

~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/vhost-net-user.c

#define MAX_VHOST_SERVER 1024
struct _vhost_server {
        struct vhost_server *server[MAX_VHOST_SERVER];
        struct fdset fdset;
        int vserver_cnt;
        pthread_mutex_t server_mutex;
};



static struct _vhost_server g_vhost_server = {
        .fdset = {
                .fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} },
                .fd_mutex = PTHREAD_MUTEX_INITIALIZER,
                .num = 0
        },
        .vserver_cnt = 0,
        .server_mutex = PTHREAD_MUTEX_INITIALIZER,
};

~~~~~~~~~~~~~~~~~


./lib/librte_vhost/vhost_user/vhost-net-user.h:43

struct vhost_server {
        char *path; /**< The path the uds is bind to. */
        int listenfd;     /**< The listener sockfd. */
};

~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.h:43

struct fdentry {
        int fd;         /* -1 indicates this entry is empty */
        fd_cb rcb;      /* callback when this fd is readable. */
        fd_cb wcb;      /* callback when this fd is writeable.*/
        void *dat;      /* fd context */
        int busy;       /* whether this entry is being used in cb. */
};


~~~~~~~~~~~~~~~~~

./lib/librte_vhost/virtio-net.c:852

/*
 * Called by main to setup callbacks when registering CUSE device.
 */
struct vhost_net_device_ops const *
get_virtio_net_callbacks(void)
{
        return &vhost_device_ops;
}

~~~~~~~~~~~~~~~~~

./lib/librte_vhost/virtio-net.c

/*
 * Function pointers are set for the device operations to allow CUSE to call
 * functions when an IOCTL, device_add or device_release is received.
 */
static const struct vhost_net_device_ops vhost_device_ops = {
        .new_device = new_device,
        .destroy_device = destroy_device,

        .set_ifname = set_ifname,

        .get_features = get_features,
        .set_features = set_features,

        .set_vring_num = set_vring_num,
        .set_vring_addr = set_vring_addr,
        .set_vring_base = set_vring_base,
        .get_vring_base = get_vring_base,

        .set_vring_kick = set_vring_kick,
        .set_vring_call = set_vring_call,

        .set_backend = set_backend,

        .set_owner = set_owner,
        .reset_owner = reset_owner,
};

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:321

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
                conn_fd, vserver_message_handler, NULL, ctx);        ------------------>  vserver_message_handler
}





###################################################################################################


1519961627178:vhost_thread1(188271)[monitor(188268)]
page 0xffffea007e000000 _count 0 flags 17fff8000004004 mapping 0x0 _mapcount -1
----------------USER------------------
 0x7ff7fb5f740d : __close_nocancel+0x24/0x57 [/lib/x86_64-linux-gnu/libpthread-2.19.so]
 0x55fff1 : user_destroy_device+0x141/0x170 [/usr/sbin/ovs-vswitchd]
 0x5517a0 : vserver_message_handler+0x1a0/0x550 [/usr/sbin/ovs-vswitchd]

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




./lib/librte_vhost/vhost_user/vhost-net-user.c


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
                user_destroy_device(ctx);        =============>    user_destroy_device
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",       ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                vhost_message_str[msg.request]);                               VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
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

        case VHOST_USER_GET_VRING_BASE:                          ------------>  VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);
                break;
        case VHOST_USER_SET_VRING_CALL:                          ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
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




------------------------------------------------------------------------------------------

lib/librte_vhost/vhost_user/virtio-net-user.c



void
user_destroy_device(struct vhost_device_ctx ctx)
{
        struct virtio_net *dev = get_device(ctx);

        if (dev && (dev->flags & VIRTIO_DEV_RUNNING))
                notify_ops->destroy_device(dev);

        if (dev && dev->mem) {
                free_mem_region(dev);         ============>   free_mem_region 
                free(dev->mem);
                dev->mem = NULL;
        }
}



static void
free_mem_region(struct virtio_net *dev)
{
        struct orig_region_map *region;
        unsigned int idx;

        if (!dev || !dev->mem)
                return;

        region = orig_region(dev->mem, dev->mem->nregions);
        for (idx = 0; idx < dev->mem->nregions; idx++) {
                if (region[idx].mapped_address) {
                        munmap((void *)(uintptr_t)region[idx].mapped_address,          <======= Gabor's debug check here
                                        region[idx].mapped_size);
                        close(region[idx].fd);
                }
        }
}


------------------------------------------------------------------------------------------


cat Ericsson_OVS_post_migration/daemon.log | cut -d':' -f5-

 VHOST_CONFIG: vhost peer closed 0

 VHOST_CONFIG: device /var/run/openvswitch/vhue0fdfafa-c7 is to be destroyed flags 0
 VHOST_CONFIG: free 3 regions
 VHOST_CONFIG: about to free region:7fee40000000 size:800000000 fd:251
 VHOST_CONFIG: munmap res=0 close res=0
 VHOST_CONFIG: about to free region:7fee00000000 size:40000000 fd:252
 VHOST_CONFIG: munmap res=0 close res=0
 VHOST_CONFIG: about to free region:7fed40000000 size:c0000000 fd:253
 VHOST_CONFIG: munmap res=0 close res=0




vhost_thread1(188271)




7fed40000000-7fee00000000   3145728 kB
7fee00000000-7fee40000000   1048576 kB
7fee40000000-7ff640000000   33554432 kB



PRE_MIG/P/188271/smaps

7fed40000000-7fee00000000 rw-s 00000000 00:1b 3458052                    /mnt/huge_qemu_1G/libvirt/qemu/qemu_back_mem._objects_ram-node0.XKa2oY (deleted)
Size:            3145728 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
Shared_Hugetlb:  3145728 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
KernelPageSize:  1048576 kB
MMUPageSize:     1048576 kB
Locked:                0 kB
VmFlags: rd wr sh mr mw me ms de ht sd
7fee00000000-7fee40000000 rw-s 00000000 00:1b 3458052                    /mnt/huge_qemu_1G/libvirt/qemu/qemu_back_mem._objects_ram-node0.XKa2oY (deleted)
Size:            1048576 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
Shared_Hugetlb:  1048576 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
KernelPageSize:  1048576 kB
MMUPageSize:     1048576 kB
Locked:                0 kB
VmFlags: rd wr sh mr mw me ms de ht sd
7fee40000000-7ff640000000 rw-s 00000000 00:1b 3458052                    /mnt/huge_qemu_1G/libvirt/qemu/qemu_back_mem._objects_ram-node0.XKa2oY (deleted)
Size:           33554432 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
Shared_Hugetlb: 33554432 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
KernelPageSize:  1048576 kB
MMUPageSize:     1048576 kB
Locked:                0 kB
VmFlags: rd wr sh mr mw me ms de ht sd


