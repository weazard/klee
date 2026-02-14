/*
 * Klee - Userspace bwrap translation layer
 * /proc/self/mountinfo generation
 *
 * Generates synthetic mountinfo entries that match the kernel format:
 *   mount_id parent_id major:minor root mount_point mount_options \
 *     optional_fields - fs_type mount_source super_options
 *
 * The ` - ` separator between optional_fields and fs_type is critical
 * for parsers like libmount (used by findmnt, systemd, etc.).
 */
#include "fuse/fuse_mountinfo.h"
#include "util/log.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

/*
 * Determine the fs_type field based on mount type.
 * For bind mounts, the fs_type is the type of the underlying filesystem,
 * which we approximate by stat()ing the source and checking known devices.
 * In practice most containers use ext4, xfs, or overlay on the host.
 */
static const char *get_fstype(const KleeMount *m)
{
    switch (m->type) {
    case MOUNT_TMPFS:
    case MOUNT_DIR:
    case MOUNT_FILE:
    case MOUNT_MQUEUE:
        return "tmpfs";
    case MOUNT_PROC:
        return "proc";
    case MOUNT_DEV:
        return "tmpfs";
    case MOUNT_OVERLAY:
    case MOUNT_TMP_OVERLAY:
    case MOUNT_RO_OVERLAY:
        return "overlay";
    default:
        break;
    }
    /* For bind mounts, we'd ideally detect the underlying fs type.
     * Use "none" as a safe default - this is what many containers show
     * for bind mounts when the real device info isn't available. */
    return "none";
}

/*
 * Get the mount_source field. For bind mounts in real bwrap, this is
 * the block device path (e.g. /dev/sda1). Since klee doesn't do real
 * mounts, we use the source path for bind mounts and the fs_type name
 * for virtual filesystems, matching common container behavior.
 */
static const char *get_mount_source(const KleeMount *m)
{
    switch (m->type) {
    case MOUNT_TMPFS:
    case MOUNT_DIR:
    case MOUNT_FILE:
        return "tmpfs";
    case MOUNT_PROC:
        return "proc";
    case MOUNT_DEV:
        return "tmpfs";
    case MOUNT_MQUEUE:
        return "mqueue";
    case MOUNT_OVERLAY:
    case MOUNT_TMP_OVERLAY:
    case MOUNT_RO_OVERLAY:
        return "overlay";
    default:
        break;
    }
    return m->source ? m->source : "none";
}

/*
 * Get mount_options (field 6, VFS-level per-mount options).
 * Format: ro|rw[,nosuid][,nodev][,noexec][,relatime]
 * Real kernel includes relatime on most mounts.
 */
static int write_mount_options(char *buf, size_t size, const KleeMount *m)
{
    const char *rw = m->is_readonly ? "ro" : "rw";

    switch (m->type) {
    case MOUNT_PROC:
        return snprintf(buf, size, "%s,nosuid,nodev,noexec,relatime", rw);
    case MOUNT_DEV:
        return snprintf(buf, size, "%s,nosuid,relatime", rw);
    case MOUNT_MQUEUE:
        return snprintf(buf, size, "%s,nosuid,nodev,noexec,relatime", rw);
    case MOUNT_TMPFS:
    case MOUNT_DIR:
    case MOUNT_FILE:
        return snprintf(buf, size, "%s,nosuid,nodev,relatime", rw);
    default:
        /* Bind mounts: bwrap always adds MS_NOSUID */
        return snprintf(buf, size, "%s,nosuid,relatime", rw);
    }
}

/*
 * Get super_options (field 11, filesystem-specific superblock options).
 * For most virtual filesystems, this is just rw or ro.
 * For tmpfs, include size and mode. For proc, just rw.
 */
static int write_super_options(char *buf, size_t size, const KleeMount *m)
{
    switch (m->type) {
    case MOUNT_TMPFS:
    case MOUNT_DIR:
    case MOUNT_FILE:
        if (m->perms)
            return snprintf(buf, size, "rw,mode=%o,inode64", m->perms);
        return snprintf(buf, size, "rw,inode64");
    case MOUNT_PROC:
        return snprintf(buf, size, "rw");
    case MOUNT_DEV:
        return snprintf(buf, size, "rw,size=65536k,mode=755,inode64");
    case MOUNT_MQUEUE:
        return snprintf(buf, size, "rw");
    default:
        /* For bind mounts, super_options reflects the underlying fs.
         * Since we don't know the real fs options, use rw. */
        return snprintf(buf, size, "rw");
    }
}

/*
 * Get the root field (field 4). For bind mounts, this is the source path
 * within the underlying filesystem. For normal mounts, it's "/".
 */
static const char *get_root_field(const KleeMount *m)
{
    switch (m->type) {
    case MOUNT_BIND_RW:
    case MOUNT_BIND_RO:
    case MOUNT_BIND_TRY:
    case MOUNT_BIND_RO_TRY:
    case MOUNT_DEV_BIND:
    case MOUNT_DEV_BIND_TRY:
    case MOUNT_BIND_DATA:
    case MOUNT_RO_BIND_DATA:
    case MOUNT_BIND_FD:
    case MOUNT_RO_BIND_FD:
        /* For bind mounts, root is the source path on the host fs */
        return m->source ? m->source : "/";
    default:
        return "/";
    }
}

/*
 * Get major:minor device numbers. For bind mounts we stat() the source
 * to get the real device. For virtual filesystems we use 0:minor with
 * a synthetic minor number.
 */
static void get_dev_numbers(const KleeMount *m, int mount_id,
                             unsigned int *major_out, unsigned int *minor_out)
{
    /* For bind mounts, try to stat the source to get real device */
    if (m->source && (m->type == MOUNT_BIND_RW || m->type == MOUNT_BIND_RO ||
        m->type == MOUNT_BIND_TRY || m->type == MOUNT_BIND_RO_TRY ||
        m->type == MOUNT_DEV_BIND || m->type == MOUNT_DEV_BIND_TRY ||
        m->type == MOUNT_BIND_DATA || m->type == MOUNT_RO_BIND_DATA ||
        m->type == MOUNT_BIND_FD || m->type == MOUNT_RO_BIND_FD)) {
        struct stat st;
        if (stat(m->source, &st) == 0) {
            *major_out = major(st.st_dev);
            *minor_out = minor(st.st_dev);
            return;
        }
    }
    /* Virtual filesystems get 0:synthetic_minor */
    *major_out = 0;
    *minor_out = (unsigned int)(mount_id + 50);
}

/* Walk the radix tree and generate mountinfo entries */
static int walk_node(const RadixNode *node, const char *prefix,
                      int parent_id,
                      char *buf, size_t buf_size, size_t *pos, int *mount_id)
{
    char path[PATH_MAX];
    if (node->component_len > 0)
        snprintf(path, sizeof(path), "%s/%.*s", prefix,
                 (int)node->component_len, node->component);
    else
        snprintf(path, sizeof(path), "%s", prefix);

    int this_id = 0;

    if (node->mount) {
        KleeMount *m = node->mount;
        this_id = *mount_id;
        const char *mount_point = m->dest ? m->dest : path;
        const char *root_field = get_root_field(m);
        const char *fstype = get_fstype(m);
        const char *mount_source = get_mount_source(m);

        unsigned int dev_major, dev_minor;
        get_dev_numbers(m, *mount_id, &dev_major, &dev_minor);

        char mount_opts[256];
        write_mount_options(mount_opts, sizeof(mount_opts), m);

        char super_opts[256];
        write_super_options(super_opts, sizeof(super_opts), m);

        /*
         * Format: mount_id parent_id major:minor root mount_point \
         *   mount_options optional_fields - fs_type mount_source super_options
         *
         * No optional_fields for our virtual mounts (no propagation).
         * The ` - ` separator is critical for libmount parsers.
         */
        int n = snprintf(buf + *pos, buf_size - *pos,
                         "%d %d %u:%u %s %s %s - %s %s %s\n",
                         *mount_id, parent_id, dev_major, dev_minor,
                         root_field, mount_point, mount_opts,
                         fstype, mount_source, super_opts);
        if (n > 0 && *pos + (size_t)n < buf_size)
            *pos += (size_t)n;
        (*mount_id)++;
    }

    int child_parent = this_id ? this_id : parent_id;
    for (RadixNode *child = node->children; child; child = child->sibling)
        walk_node(child, path, child_parent, buf, buf_size, pos, mount_id);

    return 0;
}

int klee_gen_mountinfo(const KleeMountTable *mt, char *buf, size_t buf_size)
{
    if (!mt || !buf)
        return -1;

    size_t pos = 0;
    int mount_id = 1;

    /* Start with a synthetic root entry if no root mount exists */
    RadixNode *root_node = mt->tree ? mt->tree->root : NULL;

    if (root_node) {
        /* parent_id for root mount is itself (matching kernel behavior) */
        walk_node(root_node, "", 1, buf, buf_size, &pos, &mount_id);
    }

    /* If nothing was written (no mounts), emit a minimal root entry */
    if (pos == 0) {
        int n = snprintf(buf, buf_size,
                         "1 1 0:1 / / rw,relatime - rootfs rootfs rw\n");
        if (n > 0)
            pos = (size_t)n;
    }

    return (int)pos;
}
