package com.vivo.landlocktest;

import java.util.List;

/**
 * Unified abstraction over the Landlock capability, so that
 * {@link LandlockActivity} can switch between different
 * implementations (native app-bundled interface / reflection call
 * into the framework interface) without changing business logic.
 */
public interface ILandlock {

    int getVersion();

    boolean isSupport();

    boolean isSupportNet();

    int setFileRules(List<String> readOnlyPaths, List<String> readWritePaths);

    int setPortRules(List<String> listenPorts, List<String> connectPorts);

    int canBeLandlock(String path);
}
