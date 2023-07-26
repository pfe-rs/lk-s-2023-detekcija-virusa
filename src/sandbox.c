#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mount.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sched.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <string.h>
#include <stdarg.h>

#define check(function)							\
	if((function) < 0)						\
	{								\
		fprintf(stderr, #function);				\
		fprintf(stderr, " Failed: %m\n%i\n", errno);		\
		exit(1);						\
	}
#define read_end(pipefd)	(pipefd) ? pipefd[0] : -1
#define write_end(pipefd)	(pipefd) ? pipefd[1] : -1
char **environment = NULL;
void *stack = NULL;
uid_t euid;
gid_t egid;
int flatpak_pid, flatpak_terminated, exit_code = 0;

void parse_args(int argc, char *argv[]);
char** argv_create(int argc, va_list *ptr);
size_t get_filelen(int fd);
off_t lseek_check(int fd, off_t offset, int whence);
int open_check(const char *pathname, int flags);
void stdin_redirect(int pipefd[]);
void stdout_redirect(int pipefd[]);
void stderr_redirect(int pipefd[]);

int createenv()
{
	char *map;
	ssize_t ret;
	int len, fd;

	// Map uid
	fd = open_check("/proc/self/uid_map", O_WRONLY);
	asprintf(&map, "%u %u 1\n", euid, euid);
	len = strlen(map);
	ret = write(fd, map, len);
	if (ret != len) {
		fprintf(stderr, "Cannot write to /proc/self/uid_map!\n%m\nError code: %i", errno);
		exit(1);
	}
	close(fd);
	free(map);

	// Map gid
	fd = open_check("/proc/self/setgroups", O_WRONLY);
	ret = write(fd, "deny", 4);
	if (ret != 4) {
		fprintf(stderr, "Cannot write to /proc/self/setgroups!\n%m\nError code: %i", errno);
		exit(1);
	}
	close(fd);

	fd = open_check("/proc/self/gid_map", O_WRONLY);
	asprintf(&map, "%u %u 1", egid, egid);
	len = strlen(map);
	ret = write(fd, map, len);
	if (ret != len) {
		fprintf(stderr, "Cannot write to /proc/self/gid_map!\n%m\nError code: %i", errno);
		exit(1);
	}
	close(fd);
	free(map);

	// Mount filesystems
	check( mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) )
	check( umount("/sys/fs/cgroup") )
	check( mount("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) )
}

int execute(int argc, int stdin_pipe[], int stdout_pipe[], int stderr_pipe[], ...)
{
	int pid = fork();
	if (pid == 0) {
		va_list ptr;
		va_start(ptr, stderr_pipe);
		char **argv = argv_create(argc, &ptr);
		va_end(ptr);

		stderr_redirect(stderr_pipe);
		stdin_redirect(stdin_pipe);
		stdout_redirect(stdout_pipe);

		char *path;
		asprintf(&path, "/bin/%s", argv[0]);
		execve(path, argv, environment);
		/*
		 * execve(2) failed. Try with different path and print error
		 * message if that fails too.
		 */
		free(path);
		asprintf(&path, "/sbin/%s", argv[0]);
		execve(path, argv, environment);
		fprintf(stderr, "Cannot execute %s\n%i\n%m\n", argv[0], errno);
		exit(1);
	}
	close(write_end(stdout_pipe));
	close(write_end(stderr_pipe));
	close(read_end(stdin_pipe));
	return pid;
}

void handler(int sig, siginfo_t *info, void *ucontext)
{
	if (info->si_pid == flatpak_pid) {
		if (info->si_status != 0 && info->si_status != 124)
			exit_code = info->si_status;
		else
			exit_code = 0;
		flatpak_terminated = 1;
	}
}

void copy_virus(char *path)
{
	char *viruspath;
	int fd_src, fd_dst;

	// Copy virus to the path inside Flatpak sandbox
	asprintf(&viruspath, "%s/.var/app/com.usebottles.bottles/data/bottles/bottles/Malware/drive_c/virus", getenv("HOME"));
	fd_src = open_check(path, O_RDONLY);
	fd_dst = open_check(viruspath, O_WRONLY | O_CREAT);
	check( copy_file_range(fd_src, NULL, fd_dst, NULL, get_filelen(fd_src), 0) )
	close(fd_dst);
	close(fd_src);
	free(viruspath);
}

void drop_caps()
{
	for (int cap = 0; cap < CAP_LAST_CAP; cap++) {
		check( prctl(PR_CAPBSET_DROP, cap) )
	}
	struct __user_cap_header_struct header;
	header.version = _LINUX_CAPABILITY_VERSION_3;
	header.pid = 0;
	struct __user_cap_data_struct data = { 0 };
	check( syscall(SYS_capset, &header, &data) )
}

void cgroup_kill()
{
	
}

int main_cloned(char *path)
{
	char *buf, *out, *pre_out;
	int pipefd[2];
	struct sigaction sig = { 0 };

	createenv();
	drop_caps();
	copy_virus(path);

	// Start virus in Bottles
	// Make signal handler that tells when process' immediate child terminated
	sig.sa_sigaction = handler;
	sig.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESTART;
	check( sigaction(SIGCHLD, &sig, NULL) )

	check( pipe(pipefd) )
	flatpak_pid = execute(12, NULL, NULL, pipefd, "timeout", "10", "flatpak", "run", "--command=bottles-cli", "--env=WINEDEBUG=+relay", "com.usebottles.bottles", "run", "-b", "Malware", "-e", "C:\\virus");

	buf = malloc(4097);
	buf[4096] = '\0';
	asprintf(&out, "");
	read(read_end(pipefd), &buf, 4096);
	do {
		pre_out = out;
		asprintf(&out, "%s%s", pre_out, buf);
		free(pre_out);
		if (flatpak_terminated == 2)
			break;
		if (flatpak_terminated)
			flatpak_terminated = 2;
			
	} while( read(read_end(pipefd), &buf, 4096));

	printf("%s", out);
	fflush(stdout);
	free(buf);
	cgroup_kill();
}

int main(int argc, char *argv[], char *envp[])
{
	environment = envp;
	euid = geteuid();
	egid = getegid();
	parse_args(argc, argv);
	
	// Create new process that will do the work in it's namespace
	// 136 KiB = 34 pages
	if (!stack)
		stack = mmap(NULL, 34*4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_GROWSDOWN, -1, 0);
	if (stack == MAP_FAILED) {
		fprintf(stderr, "Cannot create stack space for the new process!\n%m\nError code: %i", errno);
		exit(1);
	}

	int pid = clone(main_cloned, stack, CLONE_NEWCGROUP | CLONE_NEWNS | CLONE_NEWUSER | CLONE_VM, argv[1]);
	if (pid < 0) {
		fprintf(stderr, "Cannot create new process!\n%m\nError code: %i", errno);
		exit(2);
	}
	
	// Wait for the child to terminate
	siginfo_t status;
	check( waitid(P_PID, pid, &status, WEXITED) )
	if (status.si_code != CLD_KILLED)
		exit_code = status.si_status;
	print("%i\n", exit_code);
}

// Helper functions:

void parse_args(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Wrong arguments passed to the helper program!\n");
		exit(2);
	}
	if (getenv("HOME") == NULL) {
		fprintf(stderr, "Wrong environment passed to the helper program!\n$HOME variable missing\n");
		exit(3);
	}
}

int open_check(const char *pathname, int flags)
{
	int fd = open(pathname, flags, 0664);
	if (fd < 0) {
		fprintf(stderr, "open(%s) failed: %i\n%m", pathname, errno);
		exit(4);
	}

	return fd;
}

off_t lseek_check(int fd, off_t offset, int whence)
{
	off_t ret = lseek(fd, offset, whence);
	if (ret < 0) {
		fprintf(stderr, "lseek() failed: %i\n%m", errno);
		exit(5);
	}

	return ret;
}

size_t get_filelen(int fd)
{
	off_t cur = lseek_check(fd, 0, SEEK_CUR);
	size_t len = lseek_check(fd, 0, SEEK_END);
	lseek_check(fd, cur, SEEK_SET);

	return len;
}

char** argv_create(int argc, va_list *ptr)
{
	char** argv = malloc(sizeof(char*) * (argc+1));

	for(int i = 0; i < argc; i++)
		argv[i] = va_arg(*ptr, char*);
	argv[argc] = NULL;

	return argv;
}

void stdin_redirect(int pipefd[])
{
	close(write_end(pipefd));
	dup2(read_end(pipefd), STDIN_FILENO);
	close(read_end(pipefd));
}

void stdout_redirect(int pipefd[])
{
	close(read_end(pipefd));
	dup2(write_end(pipefd), STDOUT_FILENO);
	close(write_end(pipefd));
}

void stderr_redirect(int pipefd[])
{
	close(read_end(pipefd));
	dup2(write_end(pipefd), STDERR_FILENO);
	close(write_end(pipefd));
}
