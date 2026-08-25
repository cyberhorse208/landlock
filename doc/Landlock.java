/*
 * Copyright (C) vivo Mobile Communication Co., Ltd. All rights reserved.
 *
 * Landlock is a Linux kernel security module (Landlock LSM) that lets an
 * unprivileged process build its own sandbox to restrict its own filesystem
 * and network access. This class wraps the landlock(2) syscalls
 * (landlock_create_ruleset / landlock_add_rule / landlock_restrict_self) so
 * that they can be used from the Java layer inside vivo's customized
 * frameworks.
 *
 * Note: all the rules set by this class only take effect on the calling
 * process itself (and processes forked from it afterwards), they can never
 * be used to restrict another process.
 */

package com.vivo.framework.security;

import android.util.Log;

import java.util.List;

public class Landlock
{
    private static final String TAG = "Landlock";

    /** @hide */
    public Landlock() {
    }

    /**
     * Get the Landlock ABI version supported by the running kernel.
     * A return value <= 0 means Landlock is not supported at all.
     * @hide
     */
    public int getVersion() {
        return native_landlock_getVersion();
    }

    /**
     * Check whether the filesystem restriction ability of Landlock
     * is supported by the running kernel.
     * @hide
     */
    public boolean isSupport() {
        return native_landlock_isSupport();
    }

    /**
     * Check whether the TCP bind/connect restriction ability (introduced
     * in Landlock ABI v4) is supported by the running kernel.
     * @hide
     */
    public boolean isSupportNet() {
        return native_landlock_isSupportNet();
    }

    /**
     * Restrict the calling process' filesystem access so that only the
     * given paths remain reachable, this restriction is enforced
     * immediately and cannot be removed for the lifetime of the process
     * (and any of its children created afterwards).
     *
     * @param readOnlyPaths  paths that are allowed to be read/executed.
     * @param readWritePaths paths that are allowed to be read/written.
     * @return 0 on success, a negative value on failure.
     * @hide
     */
    public int setFileRules(List<String> readOnlyPaths, List<String> readWritePaths) {
        return native_landlock_setFileRules(readOnlyPaths, readWritePaths);
    }

    /**
     * Restrict the calling process' TCP port usage so that only the
     * given ports remain usable.
     *
     * @param listenPorts  ports that are allowed to be bound/listened on.
     * @param connectPorts ports that are allowed to be connected to.
     * @return 0 on success, a negative value on failure.
     * @hide
     */
    public int setPortRules(List<String> listenPorts, List<String> connectPorts) {
        return native_landlock_setPortRules(listenPorts, connectPorts);
    }

    /**
     * Check whether the given path exists and is accessible by the
     * calling process, i.e. whether it is worth adding a Landlock rule
     * for this path. There is no point in adding a rule for a path that
     * doesn't exist or that the process has no access to.
     *
     * @param path the path to check.
     * @return 0 if the path can be used with Landlock, a negative value
     *         otherwise.
     * @hide
     */
    public int canBeLandlock(String path) {
        return native_landlock_canBeLandlock(path);
    }

    private native int native_landlock_getVersion();
    private native boolean native_landlock_isSupport();
    private native boolean native_landlock_isSupportNet();
    private native int native_landlock_setFileRules(List<String> readOnlyPaths, List<String> readWritePaths);
    private native int native_landlock_setPortRules(List<String> listenPorts, List<String> connectPorts);
    private native int native_landlock_canBeLandlock(String path);
}
