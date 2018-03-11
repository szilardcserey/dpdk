# dpdk
./lib/librte_vhost/rte_vhost_version.map:6

DPDK_2.0 {
        global:

        rte_vhost_dequeue_burst;
        rte_vhost_driver_callback_register;
        rte_vhost_driver_register;
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




-------------------------------------------------------------------------------------------------------------------------------
./doc/guides/prog_guide/vhost_lib.rst:46


Vhost Library
=============

The vhost library implements a user space vhost driver. It supports both vhost-cuse
(cuse: user space character device) and vhost-user(user space socket server).
It also creates, manages and destroys vhost devices for corresponding virtio
devices in the guest. Vhost supported vSwitch could register callbacks to this
library, which will be called when a vhost device is activated or deactivated
by guest virtual machine.

Vhost API Overview
------------------

*   Vhost driver registration

      rte_vhost_driver_register registers the vhost driver into the system.
      For vhost-cuse, character device file will be created under the /dev directory.
      Character device name is specified as the parameter.
      For vhost-user, a Unix domain socket server will be created with the parameter as
      the local socket path.

*   Vhost session start

      rte_vhost_driver_session_start starts the vhost session loop.
      Vhost session is an infinite blocking loop.
      Put the session in a dedicate DPDK thread.

*   Callback register

      Vhost supported vSwitch could call rte_vhost_driver_callback_register to
      register two callbacks, new_destory and destroy_device.
      When virtio device is activated or deactivated by guest virtual machine,
      the callback will be called, then vSwitch could put the device onto data
      core or remove the device from data core by setting or unsetting
      VIRTIO_DEV_RUNNING on the device flags.

*   Read/write packets from/to guest virtual machine

      rte_vhost_enqueue_burst transmit host packets to guest.
      rte_vhost_dequeue_burst receives packets from guest.

*   Feature enable/disable

      Now one negotiate-able feature in vhost is merge-able.
      vSwitch could enable/disable this feature for performance consideration.




http://dpdk.readthedocs.io/en/v16.07/prog_guide/vhost_lib.html

rte_vhost_driver_register(path, flags)

This function registers a vhost driver into the system. For vhost-cuse, a /dev/path character device file will be created. For vhost-user server mode, a Unix domain socket file path will be created.




./lib/librte_vhost/vhost_user/vhost-net-user.c

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
                vserver_new_vq_conn, NULL, vserver);            =====================>   vserver_new_vq_conn

        g_vhost_server.server[g_vhost_server.vserver_cnt++] = vserver;
        pthread_mutex_unlock(&g_vhost_server.server_mutex);

        return 0;
}


-------------------------------------------------------------------------------------------------------------------------------


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
                conn_fd, vserver_message_handler, NULL, ctx);        =============>    vserver_message_handler
}



-------------------------------------------------------------------------------------------------------------------------------



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

