package com.vivo.landlocktest;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

/**
 * Simple SharedPreferences wrapper to persist which Landlock
 * implementation should be used: the app-bundled native interface,
 * or the framework interface accessed via reflection.
 */
public class LandlockPrefs {

    private static final String TAG = "LandlockPrefs";
    private static final String PREFS_NAME = "landlock_prefs";
    private static final String KEY_USE_REFLECT = "use_reflect_framework_api";

    public static boolean isUseReflect(Context context) {
        SharedPreferences sp = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return sp.getBoolean(KEY_USE_REFLECT, false);
    }

    public static void setUseReflect(Context context, boolean useReflect) {
        SharedPreferences sp = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        sp.edit().putBoolean(KEY_USE_REFLECT, useReflect).apply();
    }

    public static ILandlock createLandlock(Context context) {
        if (isUseReflect(context)) {
            Log.i(TAG, "createLandlock: using REFLECT impl (framework interface via reflection)");
            return new ReflectLandlock();
        } else {
            Log.i(TAG, "createLandlock: using NATIVE impl (app-bundled interface)");
            return new NativeLandlock();
        }
    }
}
