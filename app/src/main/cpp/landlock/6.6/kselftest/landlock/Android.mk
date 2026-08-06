LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := base_test
LOCAL_SRC_FILES := base_test.c
LOCAL_LDLIBS += -lcap
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

LOCAL_MODULE    := fs_test
LOCAL_SRC_FILES := fs_test.c

include $(BUILD_EXECUTABLE)


