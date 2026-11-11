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
    public int setFileRules(int ruleType, List<String> paths) {
        Log.d(TAG, "[native] setFileRules() called, ruleType=" + ruleType + ", paths=" + paths);
        return landlock.SetFileRules(ruleType, paths);
    }

    @Override
    public int setPortRules(int ruleType, List<String> ports) {
        Log.d(TAG, "[native] setPortRules() called, ruleType=" + ruleType + ", ports=" + ports);
        return landlock.SetPortRules(ruleType, ports);
    }

    @Override
    public int enforceRules() {
        Log.d(TAG, "[native] enforceRules() called");
        return landlock.EnforceRules();
    }

    @Override
    public int canBeLandlock(String path) {
        Log.d(TAG, "[native] canBeLandlock() called, path=" + path);
        return landlock.canBeLandlock(path);
    }
}
