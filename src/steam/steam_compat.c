/*
 * Klee - Userspace bwrap translation layer
 * Steam overlay IPC path auto-exposure implementation
 */
#include "steam/steam_compat.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

/* Steam-related paths to auto-expose */
static const char *steam_paths[] = {
    "/dev/shm",
    NULL
};

static int expose_xdg_runtime_steam(KleeMountTable *mt)
{
    const char *xdg_runtime = getenv("XDG_RUNTIME_DIR");
    if (!xdg_runtime)
        return 0;

    /* Expose steam-overlay-* directories */
    DIR *dir = opendir(xdg_runtime);
    if (!dir)
        return 0;

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, "steam-overlay-", 14) == 0) {
            char src[PATH_MAX], dest[PATH_MAX];
            snprintf(src, sizeof(src), "%s/%s", xdg_runtime, de->d_name);
            snprintf(dest, sizeof(dest), "%s/%s", xdg_runtime, de->d_name);

            struct stat st;
            if (stat(src, &st) == 0) {
                klee_mount_table_add(mt, MOUNT_BIND_RW, src, dest, false, 0755);
                KLEE_DEBUG("steam: auto-exposed %s", src);
            }
        }
    }
    closedir(dir);

    /* Expose Steam Unix domain sockets */
    char socket_path[PATH_MAX];
    snprintf(socket_path, sizeof(socket_path), "%s/steam-ipc", xdg_runtime);
    struct stat st;
    if (stat(socket_path, &st) == 0) {
        klee_mount_table_add(mt, MOUNT_BIND_RW, socket_path, socket_path,
                              false, 0755);
        KLEE_DEBUG("steam: auto-exposed %s", socket_path);
    }

    return 0;
}

static int expose_gameoverlayrenderer(KleeMountTable *mt)
{
    /* Common paths for Steam overlay library */
    const char *lib_paths[] = {
        "/usr/lib/gameoverlayrenderer.so",
        "/usr/lib64/gameoverlayrenderer.so",
        "/usr/lib32/gameoverlayrenderer.so",
        NULL
    };

    /* Also check $HOME/.steam */
    const char *home = getenv("HOME");
    char steam_lib[PATH_MAX];

    for (const char **p = lib_paths; *p; p++) {
        struct stat st;
        if (stat(*p, &st) == 0) {
            klee_mount_table_add(mt, MOUNT_BIND_RW, *p, *p, false, 0755);
            KLEE_DEBUG("steam: auto-exposed %s", *p);
        }
    }

    if (home) {
        snprintf(steam_lib, sizeof(steam_lib),
                 "%s/.steam/ubuntu12_32/gameoverlayrenderer.so", home);
        struct stat st;
        if (stat(steam_lib, &st) == 0) {
            klee_mount_table_add(mt, MOUNT_BIND_RW, steam_lib, steam_lib,
                                  false, 0755);
            KLEE_DEBUG("steam: auto-exposed %s", steam_lib);
        }

        snprintf(steam_lib, sizeof(steam_lib),
                 "%s/.steam/ubuntu12_64/gameoverlayrenderer.so", home);
        if (stat(steam_lib, &st) == 0) {
            klee_mount_table_add(mt, MOUNT_BIND_RW, steam_lib, steam_lib,
                                  false, 0755);
        }
    }

    return 0;
}

int klee_steam_auto_expose(KleeMountTable *mt)
{
    if (!mt)
        return -1;

    KLEE_INFO("auto-exposing Steam IPC paths");

    for (const char **p = steam_paths; *p; p++) {
        struct stat st;
        if (stat(*p, &st) == 0) {
            klee_mount_table_add(mt, MOUNT_BIND_RW, *p, *p, false, 0755);
            KLEE_DEBUG("steam: auto-exposed %s", *p);
        }
    }

    expose_xdg_runtime_steam(mt);
    expose_gameoverlayrenderer(mt);

    return 0;
}

int klee_steam_is_ipc_path(const char *path)
{
    if (!path)
        return 0;

    /* Check for Steam overlay patterns */
    if (strstr(path, "steam-overlay-"))
        return 1;
    if (strstr(path, "steam-ipc"))
        return 1;
    if (strstr(path, "gameoverlayrenderer"))
        return 1;
    if (strstr(path, "/dev/shm/") && strstr(path, "Steam"))
        return 1;

    return 0;
}
