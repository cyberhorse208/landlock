package com.vivo.kmirrors.security;

import java.util.List;

public class Landlock {

    /** File rule type: read-only whitelist. */
    public static final int FILE_RULE_TYPE_RO = 1;
    /** File rule type: read-write whitelist. */
    public static final int FILE_RULE_TYPE_RW = 2;

    /** Port rule type: bind whitelist. */
    public static final int PORT_RULE_TYPE_BIND = 1;
    /** Port rule type: connect whitelist. */
    public static final int PORT_RULE_TYPE_CONNECT = 2;

    static {
        System.loadLibrary("landlock");
    }

    public native int getVersion();

    public native boolean isSupport();

    public native boolean isSupportNet();

    /**
     * Add file rules for one rule type to the shared ruleset. Rules for
     * different types are merged into one ruleset which is enforced
     * only once by {@link #EnforceRules()}, because several
     * independent restrictions would intersect and deny everything.
     * An empty/null paths list means an empty whitelist for this type.
     * Not calling it keeps the capability unused.
     *
     * @param ruleType {@link #FILE_RULE_TYPE_RO} or {@link #FILE_RULE_TYPE_RW}
     * @param paths    whitelist paths, may be empty or null
     */
    public native int SetFileRules(int ruleType, List<String> paths);

    /**
     * Add port rules for one rule type to the shared ruleset. Bind and
     * connect rules are merged into one ruleset which is enforced only
     * once by {@link #EnforceRules()}.
     * An empty/null ports list means an empty whitelist for this type.
     * Not calling it keeps the capability unused.
     *
     * @param ruleType {@link #PORT_RULE_TYPE_BIND} or {@link #PORT_RULE_TYPE_CONNECT}
     * @param ports    whitelist ports, may be empty or null
     */
    public native int SetPortRules(int ruleType, List<String> ports);

    /**
     * Enforce every accumulated ruleset (file, net, and any future
     * capability) exactly once. Returns 0 when at least one ruleset was
     * prepared and every restriction was applied successfully. After a
     * successful call the rulesets cannot be extended.
     */
    public native int EnforceRules();

    public native String testString(List<String> ReadOnlyPaths, List<String> ReadWritePaths);

    // 1.path must exist
    // 2.have right access to this path.
    // if we don't, there is no need to set landlock rule for it
    public native int canBeLandlock(String path);
}
