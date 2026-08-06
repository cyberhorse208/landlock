// SPDX-License-Identifier: BSD-3-Clause
/*
 * Simple Landlock sandbox manager able to launch a process restricted by a
 * user-defined filesystem access control policy.
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2020 ANSSI
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <android/log.h>
#include <jni.h>

#define LOG_TAG "LandlockJNI"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
			const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
				    const enum landlock_rule_type rule_type,
				    const void *const rule_attr,
				    const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
					 const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define ENV_DELIMITER ":"

static int str2num(const char *numstr, __u64 *num_dst)
{
    char *endptr = nullptr;
    int err = 0;
    __u64 num;

    errno = 0;
    num = strtoull(numstr, &endptr, 10);
    if (errno != 0)
        err = errno;
        /* Was the string empty, or not entirely parsed successfully? */
    else if ((*numstr == '\0') || (*endptr != '\0'))
        err = EINVAL;
    else
        *num_dst = num;

    return err;
}

static int parse_path(char *env_path, const char ***const path_list)
{
    int i, num_paths = 0;

    if (env_path) {
        num_paths++;
        for (i = 0; env_path[i]; i++) {
            if (env_path[i] == ENV_DELIMITER[0])
                num_paths++;
        }
    }
    *path_list = static_cast<const char **>(malloc(num_paths * sizeof(**path_list)));
    if (!*path_list)
        return -1;

    for (i = 0; i < num_paths; i++)
        (*path_list)[i] = strsep(&env_path, ENV_DELIMITER);

    return num_paths;
}

/* clang-format off */

#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_TRUNCATE)
	
/* clang-format on */




static bool populate_ruleset_fs_new(char * env_path_name, const int ruleset_fd,
                                const __u64 allowed_access)
{


    int num_paths, i, ret = 1;
    const char **path_list = nullptr;
    struct landlock_path_beneath_attr path_beneath = {
            .parent_fd = -1,
    };

    if (!env_path_name) {
        /* Prevents users to forget a setting. */
        LOGE("Missing environment variable: file");
        return false;
    }
    num_paths = parse_path(env_path_name, &path_list);
    if (num_paths == 1 && path_list[0][0] == '\0') {
        free(path_list);
        LOGE("no valid paths");
        return false;
    }

    int count = 0;
    for (i = 0; i < num_paths; i++) {
        struct stat statbuf;

        path_beneath.parent_fd = open(path_list[i], O_PATH | O_CLOEXEC);
        if (path_beneath.parent_fd < 0) {
            LOGE("Failed to open \"%s\": %s\n",
                    path_list[i], strerror(errno));
            continue;
        }
        if (fstat(path_beneath.parent_fd, &statbuf)) {
            LOGE("Failed to stat \"%s\": %s", path_list[i], strerror(errno));
            close(path_beneath.parent_fd);
            continue;
        }
        path_beneath.allowed_access = allowed_access;
        if (!S_ISDIR(statbuf.st_mode))
            path_beneath.allowed_access &= ACCESS_FILE;
        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                              &path_beneath, 0)) {
            LOGE("Failed to update the ruleset with \"%s\": %s\n",
                    path_list[i], strerror(errno));
            close(path_beneath.parent_fd);
            continue;
        }
        count++;
        LOGE("%s added to ruleset with allowed_access %llu", path_list[i], allowed_access);
        close(path_beneath.parent_fd);
    }
    LOGE("add %d paths to ruleset", count);

    free(path_list);
    return count != 0;
}





static bool populate_ruleset_net_new(char * env_ports_name, const int ruleset_fd,
                                const __u64 allowed_access)
{
    char *strport;
    struct landlock_net_port_attr net_port = {
            .allowed_access = allowed_access,
    };

    if (!env_ports_name){
        LOGE("Missing environment variable: net");
        return false;
    }
    int count = 0;
    while ((strport = strsep(&env_ports_name, ENV_DELIMITER))) {
        __u64 port;

        if (strcmp(strport, "") == 0)
            continue;

        if (str2num(strport, &port)) {
            LOGE("Failed to parse port at \"%s\"\n",
                    strport);
            continue;
        }
        net_port.port = port;
        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT,
                              &net_port, 0)) {
            LOGE("Failed to update the ruleset with port \"%llu\": %s\n",
                    net_port.port, strerror(errno));
            continue;
        }
        count++;
    }

    LOGE("add %d ports to ruleset", count);
    return count != 0;
}

/* clang-format off */

#define ACCESS_FS_ROUGHLY_READ ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_WRITE ( \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM | \
	LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)
	
/* clang-format on */





extern "C"
JNIEXPORT jboolean JNICALL
Java_com_vivo_kmirrors_security_Landlock_isSupport(JNIEnv *env, jobject thiz) {
    int abi = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

// Helper function to convert a Java List<String> to a C string in "path1:path2" format
char* convertJavaListToString(JNIEnv *env, jobject pathList) {
    // Get the List class and its size method
    jclass listClass = env->GetObjectClass(pathList);
    jmethodID sizeMethod = env->GetMethodID(listClass, "size", "()I");
    jmethodID getMethod = env->GetMethodID(listClass, "get", "(I)Ljava/lang/Object;");

    // Get the size of the list
    jint listSize = env->CallIntMethod(pathList, sizeMethod);

    if (listSize == 0) {
        return nullptr;
    }
    // Determine the total length for the resulting C string
    size_t totalLength = 0;
    for (jint i = 0; i < listSize; i++) {
        jstring pathElement = (jstring)env->CallObjectMethod(pathList, getMethod, i);
        const char *pathElementCStr = env->GetStringUTFChars(pathElement, nullptr);
        totalLength += strlen(pathElementCStr) + 1; // +1 for ':' or '\0'
        env->ReleaseStringUTFChars(pathElement, pathElementCStr);
    }

    // Allocate memory for the resulting C string
    char *result = (char *)malloc(totalLength);
    if (result == nullptr) {
        return nullptr;
    }
    result[0] = '\0';

    // Concatenate paths
    for (jint i = 0; i < listSize; i++) {
        jstring pathElement = (jstring)env->CallObjectMethod(pathList, getMethod, i);
        const char *pathElementCStr = env->GetStringUTFChars(pathElement, nullptr);
        strcat(result, pathElementCStr);
        if (i < listSize - 1) {
            strcat(result, ":");
        }
        env->ReleaseStringUTFChars(pathElement, pathElementCStr);
    }

    return result;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_vivo_kmirrors_security_Landlock_SetFileRules(JNIEnv *env, jobject thiz,
                                                       jobject read_only_paths,
                                                       jobject read_write_paths) {
    int ruleset_fd;
    __u64 access_fs_ro = ACCESS_FS_ROUGHLY_READ,
            access_fs_rw = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;
    struct landlock_ruleset_attr ruleset_attr = {
            .handled_access_fs = access_fs_rw,
    };

    LOGE("Trying to create a file rw ruleset");
    int ret = 0;
    ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        LOGE("Failed to create a file rw ruleset");
        return -1;
    }

    char *roPaths = convertJavaListToString(env, read_only_paths);
    char *rwPaths = convertJavaListToString(env, read_write_paths);

    if (roPaths == nullptr) {
        LOGE("no readonly ruleset");
    } else {
        LOGE("Trying to populate a readonly ruleset");
        if (!populate_ruleset_fs_new(roPaths, ruleset_fd, access_fs_ro)) {
            LOGE("Failed to populate a readonly ruleset");
            ret = -2;
            goto out;
        }
    }

    if (rwPaths == nullptr) {
        LOGE("no readwrite ruleset");
    } else {
        LOGE("Trying to populate a readwrite ruleset");
        if (!populate_ruleset_fs_new(rwPaths, ruleset_fd, access_fs_rw)) {
            LOGE("Failed to populate a readwrite ruleset");
            ret = -3;
            goto out;
        }
    }
    LOGE("Trying to restrict privileges");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        LOGE("Failed to restrict privileges");
        ret = -4;
        goto out;
    }
    LOGE("Trying to enforce ruleset");
    if (landlock_restrict_self(ruleset_fd, 0)) {
        LOGE("Failed to enforce ruleset");
        ret = -5;
        goto out;
    }
    out:
        close(ruleset_fd);
        if(!roPaths)
            free(roPaths);
        if(!rwPaths)
            free(rwPaths);
        return ret;
}


extern "C"
JNIEXPORT jint JNICALL
Java_com_vivo_kmirrors_security_Landlock_getVersion(JNIEnv *env, jobject thiz) {
    int abi = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    return abi;
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_vivo_kmirrors_security_Landlock_testString(JNIEnv *env, jobject thiz,
                                                     jobject read_only_paths,
                                                     jobject read_write_paths) {
    char *roPaths = convertJavaListToString(env, read_only_paths);
    char *rwPaths = convertJavaListToString(env, read_write_paths);

    // 检查结果是否为 nullptr，避免程序崩溃
    if (roPaths == nullptr || rwPaths == nullptr) {
        // 处理转换错误: 返回空字符串或相应的错误信息
        return env->NewStringUTF("");
    }

    // 计算拼接后字符串的总长度
    size_t totalLength = strlen(roPaths) + strlen(rwPaths) + 1; // +1 for nullptr terminator

    // 为拼接结果分配内存
    char *result = (char *)malloc(totalLength);
    if (result == nullptr) {
        // 如果内存分配失败，返回一个空字符串，避免程序崩溃
        return env->NewStringUTF("");
    }

    // 拼接字符串
    strcpy(result, roPaths);
    strcat(result, rwPaths);

    // 将 C 字符串转换为 Java 字符串
    jstring jResult = env->NewStringUTF(result);

    // 释放分配的内存
    free(roPaths);
    free(rwPaths);
    free(result);

    return jResult;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_vivo_kmirrors_security_Landlock_canBeLandlock(JNIEnv *env, jobject thiz, jstring path) {
    struct landlock_path_beneath_attr path_beneath = {
            .parent_fd = -1,
    };
    struct stat statbuf;

    // 将 jstring 转换为 C 风格的字符串
    const char *cPath = env->GetStringUTFChars(path, nullptr);
    if (cPath == nullptr) {
        // 出现错误，内存不足
        LOGE("Failed to convert jstring to char*");
        return -1;
    }

    path_beneath.parent_fd = open(cPath, O_PATH | O_CLOEXEC);
    if (path_beneath.parent_fd < 0) {
        LOGE("Failed to open \"%s\": %s\n",
                cPath, strerror(errno));
        env->ReleaseStringUTFChars(path, cPath);
        return -2;
    }
    if (fstat(path_beneath.parent_fd, &statbuf)) {
        LOGE("Failed to stat \"%s\": %s", cPath, strerror(errno));
        close(path_beneath.parent_fd);
        env->ReleaseStringUTFChars(path, cPath);
        return -3;
    }
    close(path_beneath.parent_fd);
    env->ReleaseStringUTFChars(path, cPath);
    return 0;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_vivo_kmirrors_security_Landlock_SetPortRules(JNIEnv *env, jobject thiz,
        jobject ListenPorts,
jobject ConnectPorts){
    int ruleset_fd;
    struct landlock_ruleset_attr ruleset_attr = {
            .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
                                  LANDLOCK_ACCESS_NET_CONNECT_TCP,
    };
    LOGE("Trying to create a net ruleset");
    int ret = 0;
    ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        LOGE("Failed to create a net ruleset");
        return -1;
    }
    char *bindPorts = convertJavaListToString(env, ListenPorts);
    char *connectPorts = convertJavaListToString(env, ConnectPorts);

    LOGE("Trying to populate a LANDLOCK_ACCESS_NET_BIND_TCP ruleset");
    if (!populate_ruleset_net_new(bindPorts, ruleset_fd,
                              LANDLOCK_ACCESS_NET_BIND_TCP)) {
        LOGE("Failed to populate a LANDLOCK_ACCESS_NET_BIND_TCP ruleset");
        ret = -2;
        goto out;
    }
    LOGE("Trying to populate a LANDLOCK_ACCESS_NET_CONNECT_TCP ruleset");
    if (!populate_ruleset_net_new(connectPorts, ruleset_fd,
                              LANDLOCK_ACCESS_NET_CONNECT_TCP)) {
        LOGE("Failed to populate a LANDLOCK_ACCESS_NET_CONNECT_TCP ruleset");
        ret = -3;
        goto out;
    }
    LOGE("Trying to restrict privileges");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        LOGE("Failed to restrict privileges");
        ret = -4;
        goto out;
    }
    LOGE("Trying to enforce ruleset");
    if (landlock_restrict_self(ruleset_fd, 0)) {
        LOGE("Failed to enforce ruleset");
        ret = -5;
        goto out;
    }
    out:
    close(ruleset_fd);
    if(!bindPorts)
        free(bindPorts);
    if(!connectPorts)
        free(connectPorts);
    return ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_vivo_kmirrors_security_Landlock_isSupportNet(JNIEnv *env, jobject thiz) {
    int abi = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 4) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}
