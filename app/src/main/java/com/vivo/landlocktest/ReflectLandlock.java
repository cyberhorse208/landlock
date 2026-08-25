package com.vivo.landlocktest;

import android.util.Log;

import java.lang.reflect.Method;
import java.util.List;

/**
 * Implementation of {@link ILandlock} that accesses the framework
 * interface {@code com.vivo.framework.security.Landlock} purely via
 * reflection, so that this app does not need to compile against the
 * framework jar/sdk.
 */
public class ReflectLandlock implements ILandlock {

    private static final String TAG = "ReflectLandlock";
    private static final String CLASS_NAME = "com.vivo.framework.security.Landlock";

    private Object instance;
    private Class<?> clazz;
    private boolean available = false;

    public ReflectLandlock() {
        try {
            clazz = Class.forName(CLASS_NAME);
            instance = clazz.newInstance();
            available = true;
            Log.d(TAG, "[reflect] " + CLASS_NAME + " loaded successfully");
        } catch (Throwable e) {
            Log.e(TAG, "Failed to load " + CLASS_NAME + " via reflection: " + e);
            available = false;
        }
    }

    /**
     * @return whether the framework class/instance was successfully
     * loaded via reflection. If false, all interface methods below
     * will fail-safe and return default values.
     */
    public boolean isAvailable() {
        return available;
    }

    private Object invoke(String methodName, Class<?>[] paramTypes, Object[] args, Object defaultValue) {
        Log.d(TAG, "[reflect] " + methodName + "() called via reflection, args=" + argsToString(args));
        if (!available) {
            Log.w(TAG, "[reflect] " + methodName + "() skipped: framework class not available, returning default=" + defaultValue);
            return defaultValue;
        }
        try {
            Method method = clazz.getMethod(methodName, paramTypes);
            Object result = method.invoke(instance, args);
            Log.d(TAG, "[reflect] " + methodName + "() result=" + result);
            return result;
        } catch (Throwable e) {
            Log.e(TAG, "[reflect] " + methodName + "() invoke failed: " + e);
            return defaultValue;
        }
    }

    private static String argsToString(Object[] args) {
        if (args == null || args.length == 0) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < args.length; i++) {
            sb.append(args[i]);
            if (i != args.length - 1) {
                sb.append(", ");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    @Override
    public int getVersion() {
        Object ret = invoke("getVersion", new Class<?>[]{}, new Object[]{}, -1);
        return ret instanceof Integer ? (Integer) ret : -1;
    }

    @Override
    public boolean isSupport() {
        Object ret = invoke("isSupport", new Class<?>[]{}, new Object[]{}, false);
        return ret instanceof Boolean ? (Boolean) ret : false;
    }

    @Override
    public boolean isSupportNet() {
        Object ret = invoke("isSupportNet", new Class<?>[]{}, new Object[]{}, false);
        return ret instanceof Boolean ? (Boolean) ret : false;
    }

    @Override
    public int setFileRules(List<String> readOnlyPaths, List<String> readWritePaths) {
        Object ret = invoke("setFileRules", new Class<?>[]{List.class, List.class},
                new Object[]{readOnlyPaths, readWritePaths}, -1);
        return ret instanceof Integer ? (Integer) ret : -1;
    }

    @Override
    public int setPortRules(List<String> listenPorts, List<String> connectPorts) {
        Object ret = invoke("setPortRules", new Class<?>[]{List.class, List.class},
                new Object[]{listenPorts, connectPorts}, -1);
        return ret instanceof Integer ? (Integer) ret : -1;
    }

    @Override
    public int canBeLandlock(String path) {
        Object ret = invoke("canBeLandlock", new Class<?>[]{String.class},
                new Object[]{path}, -1);
        return ret instanceof Integer ? (Integer) ret : -1;
    }
}
