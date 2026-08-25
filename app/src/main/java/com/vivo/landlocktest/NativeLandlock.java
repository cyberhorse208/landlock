package com.vivo.landlocktest;

import android.util.Log;

import com.vivo.kmirrors.security.Landlock;

import java.util.List;

/**
 * Implementation of {@link ILandlock} that directly uses the
 * app-bundled native interface {@code com.vivo.kmirrors.security.Landlock}.
 */
public class NativeLandlock implements ILandlock {

    private static final String TAG = "NativeLandlock";

    private final Landlock landlock = new Landlock();

    @Override
    public int getVersion() {
        Log.d(TAG, "[native] getVersion() called");
        return landlock.getVersion();
    }

    @Override
    public boolean isSupport() {
        Log.d(TAG, "[native] isSupport() called");
        return landlock.isSupport();
    }

    @Override
    public boolean isSupportNet() {
        Log.d(TAG, "[native] isSupportNet() called");
        return landlock.isSupportNet();
    }

    @Override
    public int setFileRules(List<String> readOnlyPaths, List<String> readWritePaths) {
        Log.d(TAG, "[native] setFileRules() called, readOnlyPaths=" + readOnlyPaths + ", readWritePaths=" + readWritePaths);
        return landlock.SetFileRules(readOnlyPaths, readWritePaths);
    }

    @Override
    public int setPortRules(List<String> listenPorts, List<String> connectPorts) {
        Log.d(TAG, "[native] setPortRules() called, listenPorts=" + listenPorts + ", connectPorts=" + connectPorts);
        return landlock.SetPortRules(listenPorts, connectPorts);
    }

    @Override
    public int canBeLandlock(String path) {
        Log.d(TAG, "[native] canBeLandlock() called, path=" + path);
        return landlock.canBeLandlock(path);
    }
}
