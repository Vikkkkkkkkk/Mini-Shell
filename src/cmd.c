// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1
#define PATH_SIZE	1024
#define PERM		0666
#define TRUNCATE	(O_WRONLY | O_CREAT | O_TRUNC)
#define APPEND		(O_WRONLY | O_CREAT | O_APPEND)

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	if (!dir)
		return false;

	if (!dir->string)
		return false;

	if (chdir(dir->string))
		return false;

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	exit(0);
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */

static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	char dir[PATH_SIZE];

	if (s == NULL)
		return 0;

	if (s->verb->next_part) {
		setenv(s->verb->string, get_word(s->verb->next_part->next_part), 1);
		return 1;
	}

	if (strcmp(s->verb->string, "quit") == 0 || strcmp(s->verb->string, "exit") == 0)
		return shell_exit();

	if (strcmp(s->verb->string, "cd") == 0) {
		if (!getcwd(dir, sizeof(dir)))
			return 0;

		if (!s->params)
			return 0;
		if (s->params->next_part)
			return 0;

		if (s->out) {
			int out_fd = dup(STDOUT_FILENO);
			char path_out[PATH_SIZE] = "\0";

			strcat(path_out, dir);
			strcat(path_out, "/");
			strcat(path_out, s->out->string);
			if (s->out->next_part)
				strcat(path_out, get_word(s->out->next_part));

			int fd = open(path_out, TRUNCATE, PERM);

			dup2(fd, STDOUT_FILENO);
			close(fd);

			dup2(out_fd, STDOUT_FILENO);
			close(out_fd);
		}

		return shell_cd(s->params);
	}

	pid_t pid = fork();
	int status;

	if (pid == 0) {
		int argc;
		char **argv = get_argv(s, &argc);

		if (s->in) {
			int fd = -1;
			char path_in[PATH_SIZE] = "\0";

			strcat(path_in, s->in->string);
			if (s->in->next_part)
				strcat(path_in, get_word(s->in->next_part));

			fd = open(path_in, O_RDONLY);

			dup2(fd, STDIN_FILENO);
			close(fd);
		}

		if (s->out) {
			int fd = -1;
			char path_out[PATH_SIZE] = "\0";

			strcat(path_out, s->out->string);

			if (s->out->next_part)
				strcat(path_out, get_word(s->out->next_part));

			if (s->err || s->io_flags == IO_OUT_APPEND)
				fd = open(path_out, APPEND, PERM);
			else if (s->io_flags == IO_REGULAR)
				fd = open(path_out, TRUNCATE, PERM);

			dup2(fd, STDOUT_FILENO);
			close(fd);
		}

		if (s->err) {
			int fd = -1;
			char path_err[PATH_SIZE] = "\0";

			strcat(path_err, s->err->string);

			if (s->err->next_part)
				strcat(path_err, get_word(s->err->next_part));

			if (s->out || s->io_flags == IO_REGULAR)
				fd = open(path_err, TRUNCATE, PERM);
			else if (s->io_flags == IO_ERR_APPEND)
				fd = open(path_err, APPEND, PERM);

			dup2(fd, STDERR_FILENO);
			close(fd);
		}

		if (execvp(argv[0], argv) == -1) {
			printf("Execution failed for '%s'\n", argv[0]);
			exit(1);
		}
	} else {
		waitpid(pid, &status, 0);
		if (WEXITSTATUS(status) == 1)
			return 0;
		else
			return 1;
	}

	return 0;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t pid1 = fork();

	if (pid1 == 0) {
		int status = parse_command(cmd1, level + 1, father);

		exit(status);
	} else if (pid1 < 0) {
		return false;
	}

	pid_t pid2 = fork();

	if (pid2 == 0) {
		int status = parse_command(cmd2, level + 1, father);

		exit(status);
	} else if (pid2 < 0) {
		return false;
	}

	int status1, status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (WIFEXITED(status1) && WIFEXITED(status2))
		return true;
	return false;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t pid1, pid2;
	int status1, status2;
	int fd[2];

	pipe(fd);

	pid1 = fork();
	if (pid1 == 0) {
		close(fd[0]);
		dup2(fd[1], STDOUT_FILENO);
		close(fd[1]);
		exit(parse_command(cmd1, level + 1, father));
	} else if (pid1 < 0) {
		return false;
	}

	pid2 = fork();
	if (pid2 == 0) {
		close(fd[1]);
		dup2(fd[0], STDIN_FILENO);
		close(fd[0]);
		exit(parse_command(cmd2, level + 1, father));
	} else if (pid2 < 0) {
		return false;
	}

	close(fd[0]);
	close(fd[1]);
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	return WEXITSTATUS(status2);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	if (c == NULL)
		return -1;

	int out1, out2;
	bool out = true;

	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level + 1, c);

	switch (c->op) {
	case OP_SEQUENTIAL:
		out1 = parse_command(c->cmd1, level, c);
		out2 = parse_command(c->cmd2, level, c);
		return out2;

	case OP_PARALLEL:
		out = run_in_parallel(c->cmd1, c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_NZERO:
		out1 = parse_command(c->cmd1, level, c);
		if (out1 == 0) {
			out2 = parse_command(c->cmd2, level, c);
			return out2;
		}
		return out1;

	case OP_CONDITIONAL_ZERO:
		out1 = parse_command(c->cmd1, level, c);
		if (out1 == 1) {
			out2 = parse_command(c->cmd2, level, c);
			return out2;
		}
		return out1;

	case OP_PIPE:
		out = run_on_pipe(c->cmd1, c->cmd2, level, c);
		break;

	default:
		return SHELL_EXIT;
	}

	if (out)
		return 1;
	return 0;
}
