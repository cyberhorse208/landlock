// SPDX-License-Identifier: BSD-3-Clause
/*
 * Simple Landlock sandbox manager able to launch a process restricted by a
 * user-defined filesystem access control policy.
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2020 ANSSI
 */

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
#include <jni.h>

/*
 * 如果执行syscall，进程崩溃，怀疑selinux阻止调用
 */
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

#define ENV_PATH_TOKEN ":"

static int parse_path(char *env_path, const char ***const path_list)
{
	int i, num_paths = 0;

	if (env_path) {
		num_paths++;
		for (i = 0; env_path[i]; i++) {
			if (env_path[i] == ENV_PATH_TOKEN[0])
				num_paths++;
		}
	}
	*path_list = reinterpret_cast<const char **>(malloc(num_paths * sizeof(**path_list)));
	for (i = 0; i < num_paths; i++)
		(*path_list)[i] = strsep(&env_path, ENV_PATH_TOKEN);

	return num_paths;
}

/* clang-format off */

#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE)

/* clang-format on */





static int populate_ruleset_new(char * env_path_name, const int ruleset_fd,
                            const __u64 allowed_access)
{
    int num_paths, i, ret = 1;
    const char **path_list = NULL;
    struct landlock_path_beneath_attr path_beneath = {
            .parent_fd = -1,
    };

    if (!env_path_name) {
        /* Prevents users to forget a setting. */
        fprintf(stderr, "Missing environment variable\n");
        return 1;
    }
    num_paths = parse_path(env_path_name, &path_list);
    if (num_paths == 1 && path_list[0][0] == '\0') {
        /*
         * Allows to not use all possible restrictions (e.g. use
         * LL_FS_RO without LL_FS_RW).
         */
        ret = 0;
        goto out_free_name;
    }

    for (i = 0; i < num_paths; i++) {
        struct stat statbuf;

        path_beneath.parent_fd = open(path_list[i], O_PATH | O_CLOEXEC);
        if (path_beneath.parent_fd < 0) {
            fprintf(stderr, "Failed to open \"%s\": %s\n",
                    path_list[i], strerror(errno));
            goto out_free_name;
        }
        if (fstat(path_beneath.parent_fd, &statbuf)) {
            close(path_beneath.parent_fd);
            goto out_free_name;
        }
        path_beneath.allowed_access = allowed_access;
        if (!S_ISDIR(statbuf.st_mode))
            path_beneath.allowed_access &= ACCESS_FILE;
        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                              &path_beneath, 0)) {
            fprintf(stderr,
                    "Failed to update the ruleset with \"%s\": %s\n",
                    path_list[i], strerror(errno));
            close(path_beneath.parent_fd);
            goto out_free_name;
        }
        close(path_beneath.parent_fd);
    }
    ret = 0;

    out_free_name:
    free(path_list);
    free(env_path_name);
    return ret;
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
	LANDLOCK_ACCESS_FS_MAKE_SYM)
// not define in NDK r25c
//	| \
//	LANDLOCK_ACCESS_FS_REFER)

/* clang-format on */




extern "C"
JNIEXPORT jboolean JNICALL
Java_com_vivo_kmirrors_security_Landlock_isSupport(JNIEnv *env, jobject thiz) {
    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
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

    // Determine the total length for the resulting C string
    size_t totalLength = 0;
    for (jint i = 0; i < listSize; i++) {
        jstring pathElement = (jstring)env->CallObjectMethod(pathList, getMethod, i);
        const char *pathElementCStr = env->GetStringUTFChars(pathElement, NULL);
        totalLength += strlen(pathElementCStr) + 1; // +1 for ':' or '\0'
        env->ReleaseStringUTFChars(pathElement, pathElementCStr);
    }

    // Allocate memory for the resulting C string
    char *result = (char *)malloc(totalLength);
    if (result == NULL) {
        return NULL;
    }
    result[0] = '\0';

    // Concatenate paths
    for (jint i = 0; i < listSize; i++) {
        jstring pathElement = (jstring)env->CallObjectMethod(pathList, getMethod, i);
        const char *pathElementCStr = env->GetStringUTFChars(pathElement, NULL);
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

    access_fs_ro &= ruleset_attr.handled_access_fs;
    access_fs_rw &= ruleset_attr.handled_access_fs;


    ruleset_fd =
            landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        perror("Failed to create a ruleset");
        return -1;
    }

    char *roPaths = convertJavaListToString(env, read_only_paths);
    char *rwPaths = convertJavaListToString(env, read_write_paths);

    if (populate_ruleset_new(roPaths, ruleset_fd, access_fs_ro)) {
        close(ruleset_fd);
        perror("Failed to populate a readonly ruleset");
        free(roPaths);
        free(rwPaths);
        return -2;
    }
    if (populate_ruleset_new(rwPaths, ruleset_fd, access_fs_rw)) {
        close(ruleset_fd);
        perror("Failed to populate a readwrite ruleset");
        free(roPaths);
        free(rwPaths);
        return -3;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Failed to restrict privileges");
        close(ruleset_fd);
        free(roPaths);
        free(rwPaths);
        return -4;
    }
    if (landlock_restrict_self(ruleset_fd, 0)) {
        perror("Failed to enforce ruleset");
        close(ruleset_fd);
        free(roPaths);
        free(rwPaths);
        return -5;
    }
    close(ruleset_fd);
    free(roPaths);
    free(rwPaths);
    return 0;
}


extern "C"
JNIEXPORT jint JNICALL
Java_com_vivo_kmirrors_security_Landlock_getVersion(JNIEnv *env, jobject thiz) {
    return landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}