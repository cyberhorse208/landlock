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
#include <stdbool.h>

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

#define ENV_FS_RO_NAME "LL_FS_RO"
#define ENV_FS_RW_NAME "LL_FS_RW"
#define ENV_PATH_TOKEN ":"

/* Global verbose flag, enabled by -v argument. */
static bool verbose = false;

#define VLOG(fmt, ...) \
	do { if (verbose) fprintf(stderr, "[V] " fmt "\n", ##__VA_ARGS__); } while (0)

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
	*path_list = malloc(num_paths * sizeof(**path_list));
	for (i = 0; i < num_paths; i++)
		(*path_list)[i] = strsep(&env_path, ENV_PATH_TOKEN);

	return num_paths;
}

/* clang-format off */

#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_TRUNCATE)
	
/* clang-format on */

static int populate_ruleset(const char *const env_var, const int ruleset_fd,
			    const __u64 allowed_access)
{
	int num_paths, i, ret = 0;
	char *env_path_name;
	const char **path_list = NULL;
	struct landlock_path_beneath_attr path_beneath = {
		.parent_fd = -1,
	};

	env_path_name = getenv(env_var);
	if (!env_path_name) {
		/* Prevents users to forget a setting. */
		fprintf(stderr, "Missing environment variable %s\n", env_var);
		return 1;
	}
	env_path_name = strdup(env_path_name);
	unsetenv(env_var);
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

        fprintf(stderr, "populate_ruleset process \"%s\"\n",
                path_list[i]);

        struct stat statbuf;

		path_beneath.parent_fd = open(path_list[i], O_PATH | O_CLOEXEC);
		if (path_beneath.parent_fd < 0) {
			fprintf(stderr, "Failed to open \"%s\": %s\n",
				path_list[i], strerror(errno));
            ret += 1;
            continue;
			//goto out_free_name;
		}
		if (fstat(path_beneath.parent_fd, &statbuf)) {
			close(path_beneath.parent_fd);
            fprintf(stderr, "Failed to fstat \"%s\": %s\n",
                    path_list[i], strerror(errno));
            ret += 1;
            continue;
			//goto out_free_name;
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
            ret += 1;
            continue;
			//goto out_free_name;
		} else {
            fprintf(stdout,
                    "\tupdate the ruleset with \"%s\"\n",
                    path_list[i]);
        }
		close(path_beneath.parent_fd);
	}
	//ret = 0;

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
	LANDLOCK_ACCESS_FS_MAKE_SYM | \
	LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE)
	
/* clang-format on */

#define LANDLOCK_ABI_LAST 3

/*
 * Self-test action: read all content from read_path, write a message to
 * write_path. Both operations happen after the Landlock sandbox is enforced,
 * so they serve as a live test of the configured rules.
 */
static int do_self_test(const char *read_path, const char *write_path)
{
	/* ── Read file ── */
	fprintf(stderr, "\n=== [self-test] Reading: '%s' ===\n", read_path);

	FILE *in = fopen(read_path, "r");
	if (!in) {
		fprintf(stderr, "[ERROR] Cannot open '%s' for reading: %s\n",
			read_path, strerror(errno));
		return 1;
	}

	char buf[4096];
	int lines = 0;
	size_t total = 0;
	while (fgets(buf, sizeof(buf), in)) {
		if (lines == 0)
			fprintf(stderr, "--- content ---\n");
		fprintf(stderr, "%s", buf);
		total += strlen(buf);
		lines++;
	}
	if (ferror(in)) {
		fprintf(stderr, "\n[ERROR] Read error on '%s': %s\n",
			read_path, strerror(errno));
		fclose(in);
		return 1;
	}
	if (lines == 0)
		fprintf(stderr, "(file is empty)\n");
	fclose(in);
	fprintf(stderr, "--- end (%d lines, %zu bytes) ---\n", lines, total);

	fprintf(stderr, "\n");

	/* ── Write file ── */
	fprintf(stderr, "=== [self-test] Writing: '%s' ===\n", write_path);

	FILE *out = fopen(write_path, "w");
	if (!out) {
		fprintf(stderr, "[ERROR] Cannot open '%s' for writing: %s\n",
			write_path, strerror(errno));
		return 1;
	}

	const char *msg = "self-test write: sandbox is working\n";
	if (fputs(msg, out) == EOF) {
		fprintf(stderr, "[ERROR] Write error on '%s': %s\n",
			write_path, strerror(errno));
		fclose(out);
		return 1;
	}
	fclose(out);
	fprintf(stderr, "--- written: %s--- done ---\n", msg);

	return 0;
}

int main(const int argc, char *const argv[], char *const *const envp)
{
	const char *cmd_path   = NULL;
	char *const *cmd_argv  = NULL;
	const char *read_path  = NULL;
	const char *write_path = NULL;
	int ruleset_fd, abi;
	__u64 access_fs_ro = ACCESS_FS_ROUGHLY_READ,
	      access_fs_rw = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = access_fs_rw,
	};

    int ret = 0;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s=\"...\" %s=\"...\" %s [options]\n\n",
			ENV_FS_RO_NAME, ENV_FS_RW_NAME, argv[0]);
		fprintf(stderr,
			"Launch a command in a restricted environment.\n\n");
		fprintf(stderr, "Environment variables containing paths, "
				"each separated by a colon:\n");
		fprintf(stderr,
			"* %s: list of paths allowed to be used in a read-only way.\n",
			ENV_FS_RO_NAME);
		fprintf(stderr,
			"* %s: list of paths allowed to be used in a read-write way.\n",
			ENV_FS_RW_NAME);
		fprintf(stderr,
			"\nexample:\n"
			"%s=\"/bin:/lib:/usr:/proc:/etc:/dev/urandom\" "
			"%s=\"/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp\" "
			"%s bash -i\n\n",
			ENV_FS_RO_NAME, ENV_FS_RW_NAME, argv[0]);
		fprintf(stderr,
			"This can use Landlock features "
			"up to ABI version %d.\n",
			LANDLOCK_ABI_LAST);
		return 1;
	}

	/* ── Argument parsing ── */
	int i = 1;
	while (i < argc) {
		if (strcmp(argv[i], "-v") == 0) {
			verbose = true;
			i++;
		} else if (strcmp(argv[i], "-r") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: -r requires a file argument\n");
				return 1;
			}
			read_path = argv[i + 1];
			i += 2;
		} else if (strcmp(argv[i], "-w") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: -w requires a file argument\n");
				return 1;
			}
			write_path = argv[i + 1];
			i += 2;
		} else if (strcmp(argv[i], "-p") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: -p requires a command argument\n");
				return 1;
			}
			cmd_path = argv[i + 1];
			cmd_argv = (char *const *)(argv + i + 1);
			break; /* rest of argv belongs to the command */
		} else {
			/* Backward-compat: treat first non-option arg as command */
			cmd_path = argv[i];
			cmd_argv = (char *const *)(argv + i);
			break;
		}
	}

	/* ── Validate option combinations ── */
	if (cmd_path) {
		VLOG("Mode: exec  cmd='%s'", cmd_path);
	} else {
		if (!read_path || !write_path) {
			fprintf(stderr,
				"Error: no -p given; self-test mode requires both -r <file> and -w <file>\n");
			return 1;
		}
		VLOG("Mode: self-test  read='%s'  write='%s'", read_path, write_path);
	}

    fprintf(stderr,
            "Now testing some syscall:__NR_write,\n");

    const char *message = "Hello, World!\n";
    syscall(__NR_write, STDOUT_FILENO, message, strlen(message));

    fprintf(stderr,
            "Now trying to get landlock ABI version\n");

	abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		const int err = errno;

		perror("Failed to check Landlock compatibility");
		switch (err) {
		case ENOSYS:
			fprintf(stderr,
				"Hint: Landlock is not supported by the current kernel. "
				"To support it, build the kernel with "
				"CONFIG_SECURITY_LANDLOCK=y and prepend "
				"\"landlock,\" to the content of CONFIG_LSM.\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr,
				"Hint: Landlock is currently disabled. "
				"It can be enabled in the kernel configuration by "
				"prepending \"landlock,\" to the content of CONFIG_LSM, "
				"or at boot time by setting the same content to the "
				"\"lsm\" kernel parameter.\n");
			break;
		}
		return 1;
	}

	/* Best-effort security. */
	switch (abi) {
	case 1:
		/*
		 * Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2
		 *
		 * Note: The "refer" operations (file renaming and linking
		 * across different directories) are always forbidden when using
		 * Landlock with ABI 1.
		 *
		 * If only ABI 1 is available, this knowingly forbids
		 * refer operations.
		 *
		 * If a program *needs* to do refer operations after enabling
		 * Landlock, it can not use Landlock at ABI level 1.  To be
		 * compatible with different kernel versions, such programs
		 * should then fall back to not restrict themselves at all if
		 * the running kernel only supports ABI 1.
		 */
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
		__attribute__((fallthrough));
	case 2:
		/* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;

		fprintf(stderr,
			"Hint: You should update the running kernel "
			"to leverage Landlock features "
			"provided by ABI version %d (instead of %d).\n",
			LANDLOCK_ABI_LAST, abi);
		__attribute__((fallthrough));
	case LANDLOCK_ABI_LAST:
        fprintf(stderr,
                "current landlock ABI %d. this program leverage ABI %d. \n",
                abi, LANDLOCK_ABI_LAST);
		break;
	default:
		fprintf(stderr,
			"Hint: You should update this  "
			"to leverage Landlock features "
			"provided by ABI version %d (instead of %d).\n",
			abi, LANDLOCK_ABI_LAST);
	}
	access_fs_ro &= ruleset_attr.handled_access_fs;
	access_fs_rw &= ruleset_attr.handled_access_fs;

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (ruleset_fd < 0) {
		perror("Failed to create a ruleset");
		return 1;
	}

    fprintf(stderr,"now populate rules in LL_FS_RO\n");
    ret = populate_ruleset(ENV_FS_RO_NAME, ruleset_fd, access_fs_ro);
	if (ret) {
        fprintf(stderr,"%d paths not populated in LL_FS_RO\n", ret);
        //perror("run with no LL_FS_RO");
		//goto err_close_ruleset;
	}
    fprintf(stderr,"now populate rules in LL_FS_RW\n");
    ret = populate_ruleset(ENV_FS_RW_NAME, ruleset_fd, access_fs_rw);
	if (ret) {
        fprintf(stderr,"%d paths not populated in LL_FS_RW\n", ret);
		//perror("run with no LL_FS_RW");
		//goto err_close_ruleset;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("Failed to restrict privileges");
		goto err_close_ruleset;
	}
	if (landlock_restrict_self(ruleset_fd, 0)) {
		perror("Failed to enforce ruleset");
		goto err_close_ruleset;
	}
	close(ruleset_fd);

	/* ── Post-sandbox action ── */
	if (!cmd_path) {
		return do_self_test(read_path, write_path);
	}

    VLOG("Sandbox active. Executing command: %s", cmd_path);
    fprintf(stderr,"\n\nafter populate ruleset, let's start new process to run %s %s\n\n", cmd_path, cmd_argv);
	execvpe(cmd_path, cmd_argv, envp);
	fprintf(stderr, "Failed to execute \"%s\": %s\n", cmd_path,
		strerror(errno));
	fprintf(stderr, "Hint: access to the binary, the interpreter or "
			"shared libraries may be denied.\n");
	return 1;

err_close_ruleset:
    perror("Something goes wrong, exit!\n");
	close(ruleset_fd);
	return 1;
}
