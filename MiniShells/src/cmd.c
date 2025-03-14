// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "cmd.h"
#include "utils.h"

#define READ        0
#define WRITE       1

/**
 * Internal change-directory command.
 * If no argument is given, cd to $HOME.
 */
static bool shell_cd(word_t *dir)
{
    char cwd[PATH_MAX];

    if (dir == NULL) {
        /* go to $HOME by default */
        char *home = getenv("HOME");
        if (!home) {
            fprintf(stderr, "cd: HOME not set\n");
            return false;
        }

        if (chdir(home) != 0) {
            perror("cd");
            return false;
        }

        /* update PWD after successful chdir */
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            setenv("PWD", cwd, 1);
        } else {
            perror("cd: getcwd failed");
            return false;
        }

        return true;
    }

    char *path = get_word(dir);
    if (path == NULL) {
        fprintf(stderr, "cd: memory allocation error\n");
        return false;
    }

    if (chdir(path) != 0) {
        perror("cd");
        free(path);
        return false;
    }

    /* update PWD after successful chdir */
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        setenv("PWD", cwd, 1);
    } else {
        perror("cd: getcwd failed");
        free(path);
        return false;
    }

    free(path);
    return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(simple_command_t *s)
{
    int exit_code = 0;

    if (s->params != NULL) {
        word_t *param = s->params;
        if (param->next_word != NULL) {
            fprintf(stderr, "exit: too many arguments\n");
            return 1;
        }

        char *arg = get_word(param);
        if (arg == NULL) {
            fprintf(stderr, "exit: memory allocation error\n");
            return 1;
        }

        exit_code = atoi(arg);
        free(arg);
    }

    exit(exit_code);
    /* not reached */
    return SHELL_EXIT;
}

/**
 * Helper function to detect and handle a single "VAR=value" assignment
 * Returns:
 *    1 -> not an assignment
 *    0 -> it was an assignment and successfully set
 *   -1 -> it was an assignment but an error occurred
 */
static int try_setenv_from_string(char *cmd_str)
{
    /* Look for '=' e.g., "VAR=value" */
    char *eq_ptr = strchr(cmd_str, '=');
    if (!eq_ptr)
        return 1; /* not an assignment */

    /*
     * treat everything before '=' as the variable name
     * and everything after '=' as the value.
     */
    *eq_ptr = '\0';      /* split the string in-place */
    char *var_name = cmd_str;
    char *var_value = eq_ptr + 1;

    /* if var_name is empty: skip */
    if (*var_name == '\0') {
        fprintf(stderr, "Invalid assignment: missing variable name\n");
        return -1;
    }

    /* Set or overwrite the variable */
    if (setenv(var_name, var_value, 1) != 0) {
        perror("setenv");
        return -1;
    }

    return 0;
}

/**
 * Helper function to handle redirections in external commands or built-ins
 * Returns true on success, false on failure.
 */
static bool handle_redirections(simple_command_t *s)
{
    /* 1) input redirection:*/
    if (s->in) {
        char *in_file = get_word(s->in);
        if (!in_file) {
            fprintf(stderr, "parse_simple: memory allocation error\n");
            return false;
        }
        int fd_in = open(in_file, O_RDONLY);
        if (fd_in < 0) {
            perror("open for input redirection");
            free(in_file);
            return false;
        }
        if (dup2(fd_in, STDIN_FILENO) < 0) {
            perror("dup2 for input redirection");
            close(fd_in);
            free(in_file);
            return false;
        }
        close(fd_in);
        free(in_file);
    }

    /* 2) output/error redirection: */
    char *out_file = NULL;
    char *err_file = NULL;

    if (s->out) {
        out_file = get_word(s->out);
        if (!out_file) {
            fprintf(stderr, "parse_simple: memory allocation error\n");
            return false;
        }
    }
    if (s->err) {
        err_file = get_word(s->err);
        if (!err_file) {
            fprintf(stderr, "parse_simple: memory allocation error\n");
            free(out_file);
            return false;
        }
    }

    /* if out_file and err_file refer to the same path => unify them */
    if (out_file && err_file && strcmp(out_file, err_file) == 0) {
        int flags = O_WRONLY | O_CREAT;
        if (s->io_flags & IO_OUT_APPEND || s->io_flags & IO_ERR_APPEND)
            flags |= O_APPEND;
        else
            flags |= O_TRUNC;

        int fd = open(out_file, flags, 0644);
        if (fd < 0) {
            perror("open for output+error redirection");
            free(out_file);
            free(err_file);
            return false;
        }
        if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
            perror("dup2 for output/error redirection");
            close(fd);
            free(out_file);
            free(err_file);
            return false;
        }
        close(fd);
        free(out_file);
        free(err_file);
    } else {
        /* handling for stdout and stderr */
        if (out_file) {
            int flags = O_WRONLY | O_CREAT;
            if (s->io_flags & IO_OUT_APPEND)
                flags |= O_APPEND;
            else
                flags |= O_TRUNC;

            int fd_out = open(out_file, flags, 0644);
            if (fd_out < 0) {
                perror("open for output redirection");
                free(out_file);
                if (err_file) free(err_file);
                return false;
            }
            if (dup2(fd_out, STDOUT_FILENO) < 0) {
                perror("dup2 for output redirection");
                close(fd_out);
                free(out_file);
                if (err_file) free(err_file);
                return false;
            }
            close(fd_out);
            free(out_file);
        }

        if (err_file) {
            int flags = O_WRONLY | O_CREAT;
            if (s->io_flags & IO_ERR_APPEND)
                flags |= O_APPEND;
            else
                flags |= O_TRUNC;

            int fd_err = open(err_file, flags, 0644);
            if (fd_err < 0) {
                perror("open for error redirection");
                free(err_file);
                return false;
            }
            if (dup2(fd_err, STDERR_FILENO) < 0) {
                perror("dup2 for error redirection");
                close(fd_err);
                free(err_file);
                return false;
            }
            close(fd_err);
            free(err_file);
        }
    }

    return true;
}

/**
 * Helper function to handle redirections for built-in commands
 * Temporarily redirects stdout and stderr, executes the built-in, and restores the original descriptors.
 * Returns the exit status of the built-in command.
 */
static int execute_builtin_with_redirection(simple_command_t *s, bool is_cd, bool is_exit)
{
    int saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) {
        perror("dup");
        return 1;
    }

    int saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0) {
        perror("dup");
        close(saved_stdout);
        return 1;
    }

    /* handle redirections */
    if (!handle_redirections(s)) {
        /* restore original stdout and stderr */
        dup2(saved_stdout, STDOUT_FILENO);
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stdout);
        close(saved_stderr);
        return 1;
    }

    /* execute the built-in command */
    int ret = 0;
    if (is_cd) {
        ret = shell_cd(s->params) ? 0 : 1;
    } else if (is_exit) {
        /* shell_exit does not return */
        shell_exit(s);
    }

    /* restore original stdout and stderr */
    if (dup2(saved_stdout, STDOUT_FILENO) < 0) {
        perror("dup2");
        ret = 1;
    }
    if (dup2(saved_stderr, STDERR_FILENO) < 0) {
        perror("dup2");
        ret = 1;
    }

    close(saved_stdout);
    close(saved_stderr);

    return ret;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * or external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
    if (!s || !s->verb) {
        fprintf(stderr, "parse_simple: invalid simple command structure\n");
        return 1;
    }

    /* extract command string */
    char *cmd = get_word(s->verb);
    if (!cmd) {
        fprintf(stderr, "parse_simple: memory allocation error\n");
        return 1;
    }

    /* check for built-ins first: cd, exit, quit */
    if (strcmp(cmd, "cd") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        bool is_cd = strcmp(cmd, "cd") == 0;
        bool is_exit = strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0;

        // check if any redirections are present
        bool has_redirection = (s->in != NULL) || (s->out != NULL) || (s->err != NULL);

        if (has_redirection) {
            /* execute built-in with redirections in the parent process */
            int ret = execute_builtin_with_redirection(s, is_cd, is_exit);
            free(cmd);
            return ret;
        }

        /* no redirections: execute built-in directly */
        if (is_cd) {
            bool success = shell_cd(s->params);
            free(cmd);
            return success ? 0 : 1;
        }

        if (is_exit) {
            int exit_code = shell_exit(s);
            free(cmd);
            return exit_code;
        }
    }

    /* check: assignment like "VAR=value" */
    {
        int assign_ret = try_setenv_from_string(cmd);
        if (assign_ret == 0) {
            free(cmd);
            return 0;
        } else if (assign_ret == -1) {
            free(cmd);
            return 1;
        }
    }

    /* treat it as an external command */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        free(cmd);
        return 1;
    }

    if (pid == 0) {
        /* Child process */

        /* Handle redirections (input, output, error) */
        if (!handle_redirections(s)) {
            exit(1);
        }

        /* build argv and exec */
        int argc;
        char **argv = get_argv(s, &argc);
        if (!argv) {
            fprintf(stderr, "parse_simple: memory allocation error\n");
            exit(1);
        }

        execvp(argv[0], argv);
        /* it's an error => unknown command */
        fprintf(stderr, "Execution failed for '%s'\n", argv[0]);
        for (int i = 0; i < argc; i++)
            free(argv[i]);
        free(argv);
        exit(127);

    } else {
        /* Parent process */
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid");
            free(cmd);
            return 1;
        }
        free(cmd);

        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        else
            return 1;
    }
}

/**
 * Process two commands in parallel, by creating two children.
 * Returns true if both commands succeed, false otherwise.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
                            command_t *father)
{
    pid_t pid1, pid2;
    int status1, status2;

    pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        return false;
    }

    if (pid1 == 0) {
        // first child
        int ret = parse_command(cmd1, level + 1, father);
        exit(ret);
    }

    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        return false;
    }

    if (pid2 == 0) {
        // second child
        int ret = parse_command(cmd2, level + 1, father);
        exit(ret);
    }

    // parent process waits for both children
    if (waitpid(pid1, &status1, 0) < 0) {
        perror("waitpid");
        return false;
    }

    if (waitpid(pid2, &status2, 0) < 0) {
        perror("waitpid");
        return false;
    }

    // check exit statuses (both must be zero for success)
    if (WIFEXITED(status1) && WIFEXITED(status2)) {
        return (WEXITSTATUS(status1) == 0 && WEXITSTATUS(status2) == 0);
    }

    return false;
}

/**
 * Run commands by creating a pipe (cmd1 | cmd2).
 * Return the exit code of the **second** command to mimic real shells.
 */
static int run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
                       command_t *father)
{
    int pipefd[2];
    pid_t pid1, pid2;
    int status1, status2;

    if (pipe(pipefd) < 0) {
        perror("pipe");
        return 1;
    }

    pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        return 1;
    }

    if (pid1 == 0) {
        // first child: execute cmd1
        // redirect stdout to pipe write-end
        if (dup2(pipefd[WRITE], STDOUT_FILENO) < 0) {
            perror("dup2");
            exit(1);
        }

        // close unused pipe ends
        close(pipefd[READ]);
        close(pipefd[WRITE]);

        int ret = parse_command(cmd1, level + 1, father);
        exit(ret);
    }

    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        return 1;
    }

    if (pid2 == 0) {
        // second child: execute cmd2
        // redirect stdin to pipe read-end
        if (dup2(pipefd[READ], STDIN_FILENO) < 0) {
            perror("dup2");
            exit(1);
        }

        // close unused pipe ends
        close(pipefd[READ]);
        close(pipefd[WRITE]);

        int ret = parse_command(cmd2, level + 1, father);
        exit(ret);
    }

    // parent process: close both ends
    close(pipefd[READ]);
    close(pipefd[WRITE]);

    // wait for both children
    if (waitpid(pid1, &status1, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    if (waitpid(pid2, &status2, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFEXITED(status2))
        return WEXITSTATUS(status2);

    return 1;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
    if (c == NULL) {
        fprintf(stderr, "parse_command: command is NULL\n");
        return 1;
    }

    if (c->op == OP_NONE) {
        // simple command:
        return parse_simple(c->scmd, level, c);
    }

    switch (c->op) {
    case OP_SEQUENTIAL: {
        int status1 = parse_command(c->cmd1, level + 1, c);
        if (status1 != SHELL_EXIT) {
            return parse_command(c->cmd2, level + 1, c);
        }
        return SHELL_EXIT;
    }

    case OP_PARALLEL: {
        bool success = run_in_parallel(c->cmd1, c->cmd2, level, c);
        return success ? 0 : 1;
    }

    case OP_CONDITIONAL_NZERO: {
        int status1 = parse_command(c->cmd1, level + 1, c);
        if (status1 != 0) {
            return parse_command(c->cmd2, level + 1, c);
        }
        return status1;
    }

    case OP_CONDITIONAL_ZERO: {
        int status1 = parse_command(c->cmd1, level + 1, c);
        if (status1 == 0) {
            return parse_command(c->cmd2, level + 1, c);
        }
        return status1;
    }

    case OP_PIPE: {
        return run_on_pipe(c->cmd1, c->cmd2, level, c);
    }

    default:
        fprintf(stderr, "parse_command: unknown operator\n");
        return SHELL_EXIT;
    }

    /* Should never reach here */
    return 0;
}
