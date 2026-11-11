package com.vivo.landlocktest;

import java.util.List;

/**
 * Unified abstraction over the Landlock capability, so that
 * {@link LandlockActivity} can switch between different
 * implementations (native app-bundled interface / reflection call
 * into the framework interface) without changing business logic.
 */
public interface ILandlock {

    int FILE_RULE_TYPE_RO = 1;
    int FILE_RULE_TYPE_RW = 2;
    int PORT_RULE_TYPE_BIND = 1;
    int PORT_RULE_TYPE_CONNECT = 2;

    int getVersion();

    boolean isSupport();

    boolean isSupportNet();

    /**
     * @param ruleType {@link #FILE_RULE_TYPE_RO} or {@link #FILE_RULE_TYPE_RW}
     * @param paths    whitelist paths; an empty/null list means an empty whitelist
     */
    int setFileRules(int ruleType, List<String> paths);

    /**
     * @param ruleType {@link #PORT_RULE_TYPE_BIND} or {@link #PORT_RULE_TYPE_CONNECT}
     * @param ports    whitelist ports; an empty/null list means an empty whitelist
     */
    int setPortRules(int ruleType, List<String> ports);

    /**
     * Enforce every accumulated ruleset (file, net, and any future
     * capability) exactly once. Returns 0 when at least one ruleset was
     * prepared and every restriction was applied successfully. After a
     * successful call the rulesets cannot be extended.
     */
    int enforceRules();

    int canBeLandlock(String path);
}
