// SPDX-License-Identifier: BSD-3-Clause
/*
 * Simple Landlock sandbox test helper: reads a file and writes another.
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2020 ANSSI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -r <file-to-read> -w <file-to-write>\n"
            "\n"
            "Options:\n"
            "  -r <file>   File to read and print to stderr\n"
            "  -w <file>   File to write a timestamped message into\n",
            prog);
}

int main(const int argc, char *const argv[])
{
    const char *read_path  = NULL;
    const char *write_path = NULL;

    /* ── Argument parsing ── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[ERROR] -r requires a file argument\n");
                print_usage(argv[0]);
                return 1;
            }
            read_path = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-w") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[ERROR] -w requires a file argument\n");
                print_usage(argv[0]);
                return 1;
            }
            write_path = argv[i + 1];
            i++;
        } else {
            fprintf(stderr, "[ERROR] Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!read_path || !write_path) {
        fprintf(stderr, "[ERROR] Both -r and -w are required\n");
        print_usage(argv[0]);
        return 1;
    }

    /* ── Read input file ── */
    fprintf(stderr, "\n=== try to read file: '%s' ===\n", read_path);

    FILE *input_file = fopen(read_path, "r");
    if (input_file == NULL) {
        fprintf(stderr, "[ERROR] Failed to open input file '%s': ", read_path);
        perror("");
        //return 1;
    } else {
        char buffer[4096];
        size_t total_chars = 0;
        int line_count = 0;

        while (fgets(buffer, sizeof(buffer), input_file) != NULL) {
            fprintf(stderr, "%s", buffer);
            total_chars += strlen(buffer);
            line_count++;
        }

        fclose(input_file);
        fprintf(stderr, "\n===read finished (%d lines, %zu bytes) ===\n", line_count, total_chars);
    }

    /* ── Write output file ── */
    fprintf(stderr, "=== try to write file: '%s' ===\n", write_path);

    FILE *output_file = fopen(write_path, "w");
    if (output_file == NULL) {
        fprintf(stderr, "[ERROR] Failed to open output file '%s': ", write_path);
        perror("");
        //return 1;
    } else {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

        char message[128];
        snprintf(message, sizeof(message), "hello world [%s]\n", time_str);

        if (fputs(message, output_file) == EOF) {
            fprintf(stderr, "[ERROR] Failed to write to output file '%s': ", write_path);
            perror("");
            fclose(output_file);
            //return 1;
        }

        fclose(output_file);
        fprintf(stderr, "\n=== written content: %s--- done ===\n", message);
    }

    return 0;
}
