LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := sandboxer
LOCAL_SRC_FILES := sandboxer.c

include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

LOCAL_MODULE    := sandboxer-test
LOCAL_SRC_FILES := ../sandboxer-test.c

include $(BUILD_EXECUTABLE)



include $(CLEAR_VARS)
LOCAL_LDLIBS += -llog
LOCAL_MODULE    := landlock
LOCAL_SRC_FILES := landlock-jni.cpp

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE    := listener
LOCAL_SRC_FILES := ../listener.c
LOCAL_LDFLAGS   := -static

include $(BUILD_EXECUTABLE)
