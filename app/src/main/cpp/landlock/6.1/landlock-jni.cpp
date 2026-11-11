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
        /* An empty/null list means an empty whitelist (deny by default). */
        fprintf(stderr, "empty path list, whitelist will be empty\n");
        return 0;
    }
    num_paths = parse_path(env_path_name, &path_list);
    if (num_paths == 1 && path_list[0][0] == '\0') {
        /* An empty list means an empty whitelist. */
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
    /* env_path_name is owned (and freed) by the caller. */
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
    if (pathList == NULL) {
        // Treated as an empty list: an empty whitelist.
        return strdup("");
    }
    // Get the List class and its size method
    jclass listClass = env->GetObjectClass(pathList);
    jmethodID sizeMethod = env->GetMethodID(listClass, "size", "()I");
    jmethodID getMethod = env->GetMethodID(listClass, "get", "(I)Ljava/lang/Object;");

    // Get the size of the list
    jint listSize = env->CallIntMethod(pathList, sizeMethod);

    if (listSize == 0) {
        // An empty list maps to an empty string: an empty whitelist.
        return strdup("");
    }

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

/* File rule types accepted by SetFileRules(). */
#define LANDLOCK_FILE_RULE_TYPE_RO 1
#define LANDLOCK_FILE_RULE_TYPE_RW 2

/*
 * Shared (not yet enforced) ruleset for the file capability. All rule
 * types (RO/RW) are accumulated into this single ruleset so that the
 * final restriction is applied only once with the union of all rules.
 * Restricting several independent rulesets would intersect them and
 * deny everything, because Landlock rules can only be narrowed.
 */
static int g_file_ruleset_fd = -1;

/*
 * Set file rules for a single rule type.
 * rule_type: 1 = read-only, 2 = read-write.
 * Semantics: calling this method adds rules to the shared file
 * ruleset; an empty paths list means an empty whitelist for this type
 * (no path is allowed). The ruleset is enforced by EnforceFileRules().
 */
extern "C"
JNIEXPORT jint JNICALL
Java_com_vivo_kmirrors_security_Landlock_SetFileRules(JNIEnv *env, jobject thiz,
                                                       jint rule_type, jobject paths) {
    __u64 access_fs_ro = ACCESS_FS_ROUGHLY_READ,
            access_fs_rw = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;
    __u64 allowed_access;
    struct landlock_ruleset_attr ruleset_attr = {
            .handled_access_fs = access_fs_rw,
    };

    switch (rule_type) {
    case LANDLOCK_FILE_RULE_TYPE_RO:
        allowed_access = access_fs_ro;
        break;
    case LANDLOCK_FILE_RULE_TYPE_RW:
        allowed_access = access_fs_rw;
        break;
    default:
        fprintf(stderr, "invalid file rule type: %d\n", rule_type);
        return -1;
    }
    allowed_access &= ruleset_attr.handled_access_fs;

    if (g_file_ruleset_fd < 0) {
        g_file_ruleset_fd =
                landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
        if (g_file_ruleset_fd < 0) {
            perror("Failed to create a ruleset");
            return -1;
        }
    }

    char *pathList = convertJavaListToString(env, paths);
    if (pathList == NULL) {
        perror("Failed to convert the path list");
        return -2;
    }

    /* An empty list keeps an empty whitelist for this type. */
    if (populate_ruleset_new(pathList, g_file_ruleset_fd, allowed_access)) {
        perror("Failed to populate the file ruleset");
        free(pathList);
        return -3;
    }
    free(pathList);
    return 0;
}

/*
 * Enforce every accumulated shared ruleset (currently only the file
 * ruleset; any future capability joins here) exactly once. Returns 0
 * when at least one ruleset was prepared and every restriction was
 * applied successfully; after a successful call the rulesets are
 * closed and cannot be extended.
 */
extern "C"
JNIEXPORT jint JNICALL
Java_com_vivo_kmirrors_security_Landlock_EnforceRules(JNIEnv *env, jobject thiz) {
    if (g_file_ruleset_fd < 0) {
        fprintf(stderr, "no ruleset prepared\n");
        return -1;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Failed to restrict privileges");
        return -2;
    }
    if (landlock_restrict_self(g_file_ruleset_fd, 0)) {
        perror("Failed to enforce ruleset");
        close(g_file_ruleset_fd);
        g_file_ruleset_fd = -1;
        return -3;
    }
    close(g_file_ruleset_fd);
    g_file_ruleset_fd = -1;
    return 0;
}


extern "C"
JNIEXPORT jint JNICALL
Java_com_vivo_kmirrors_security_Landlock_getVersion(JNIEnv *env, jobject thiz) {
    return landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}