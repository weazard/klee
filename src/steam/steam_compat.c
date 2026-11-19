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
#include <unistd.h>

static void expose_path(KleeMountTable *mt, const char *path, bool allow_dev_shm)
{
    KleeMount *mount = klee_mount_table_resolve(mt, path);
    if (mount && !(allow_dev_shm && mount->type == MOUNT_DEV))
        return;
    if (access(path, F_OK) == 0 &&
        klee_mount_table_add(mt, MOUNT_BIND_RW, path, path, false, 0755) == 0)
        KLEE_DEBUG("steam: auto-exposed %s", path);
}

static void expose_runtime_sockets(KleeMountTable *mt)
{
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    if (!runtime || !*runtime)
        return;

    DIR *dir = opendir(runtime);
    if (!dir)
        return;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, "steam-overlay-", 14) == 0 ||
            strcmp(de->d_name, "steam-ipc") == 0) {
            char path[PATH_MAX];
            int n = snprintf(path, sizeof(path), "%s/%s", runtime, de->d_name);
            if (n > 0 && (size_t)n < sizeof(path))
                expose_path(mt, path, false);
        }
    }
    closedir(dir);
}

static void expose_gameoverlayrenderer(KleeMountTable *mt)
{
    static const char *const libs[] = {
        "/usr/lib/gameoverlayrenderer.so",
        "/usr/lib64/gameoverlayrenderer.so",
        "/usr/lib32/gameoverlayrenderer.so",
        NULL
    };
    for (const char *const *p = libs; *p; p++)
        expose_path(mt, *p, false);

    const char *home = getenv("HOME");
    if (!home || !*home)
        return;
    for (int bits = 32; bits <= 64; bits += 32) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/.steam/ubuntu12_%d/gameoverlayrenderer.so",
                         home, bits);
        if (n > 0 && (size_t)n < sizeof(path))
            expose_path(mt, path, false);
    }
}

int klee_steam_auto_expose(KleeMountTable *mt)
{
    if (!mt)
        return -1;

    bool steam = getenv("SteamAppId") || getenv("STEAM_RUNTIME") ||
                 getenv("STEAM_COMPAT_DATA_PATH") || getenv("PRESSURE_VESSEL_RUNTIME");
    if (steam) {
        expose_path(mt, "/dev/shm", true);
        expose_runtime_sockets(mt);
        expose_gameoverlayrenderer(mt);
    }
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
