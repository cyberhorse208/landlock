package com.vivo.kmirrors.security;

import java.util.List;

public class Landlock {
    static {
        System.loadLibrary("landlock");
    }

    public native int getVersion();

    public native boolean isSupport();

    public native boolean isSupportNet();

    public native int SetFileRules(List<String> ReadOnlyPaths, List<String> ReadWritePaths);

    public native int SetPortRules(List<String> ListenPorts, List<String> ConnectPorts);

    public native String testString(List<String> ReadOnlyPaths, List<String> ReadWritePaths);

    // 1.path must exist
    // 2.have right access to this path.
    // if we don't, there is no need to set landlock rule for it
    public native int canBeLandlock(String path);
}
