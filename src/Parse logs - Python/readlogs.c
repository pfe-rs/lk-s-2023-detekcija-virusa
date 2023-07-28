#define _GNU_SOURCE
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#define REGION_SIZE (size_t) 1*1024*1024*1024*1024

// Syscall wrapper functions:
static void chdir_check(const char *path);
static int fchdir_check(int fd);
static off_t lseek_check(int fd, off_t offset, int whence);
static int open_check(const char *path, int flags);
static ssize_t read_check(int fd, void *buf, size_t count);

// Other global identifiers:
char *strace_output = NULL;

static size_t get_filelen(int fd)
{
	off_t cur = lseek_check(fd, 0, SEEK_CUR);
	size_t len = lseek_check(fd, 0, SEEK_END);
	lseek_check(fd, cur, SEEK_SET);

	return len;
}

const char *parse_strace_line(char *line)
{
	size_t i, len;
	int escape = 0, in_string = 0;

	len = strlen(line);
	for(i = 0; i < len; i++) {
		// Skip string literals, but remove "" around them
		if (line[i] == '\\' && !escape && in_string) {
			escape = 1;
			continue;
		}
		if (escape) {
			escape = 0;
			continue;
		}
		if (line[i] == '\"') {
			in_string = !in_string;
			line[i] = ' ';
			continue;
		}
		if (in_string)
			continue;

		// Turn 'x' that is left from hex numbers (0x454) into candidate for removal
		if (i < len-1)
			if (line[i] == '0' && line[i+1] == 'x')
				line[i+1] = '.';

		// Keep certain chars
		if (line[i] >= 'a' && line[i] <= 'z')
			continue;
		if (line[i] >= 'A' && line[i] <= 'Z')
			continue;
		if (line[i] == '_')
			continue;

		// Replace everything else with whitespace
		line[i] = ' ';
	}

	return line;
}

const char *read_strace_log(const char *dirpath)
{
	struct dirent *entry;
	size_t total_size = 0, size;
	int fd, dirfd;
	DIR *dirp;
	
	// Open current directory, so that we can come back there later
	dirfd = open_check(".", O_RDONLY | O_DIRECTORY);
	// Allocate string 
	if (!strace_output)
		strace_output = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
	if (strace_output == MAP_FAILED) {
		fprintf(stderr, "Cannot allocate space for the string!\n%m\nError code: %i", errno);
		exit(1);
	}

	// Open directory with logs
	dirp = opendir(dirpath);
	if (dirp == NULL) {
		fprintf(stderr, "Error: Cannot open given directory\n%m\n");
		exit(2);
	}

	// Read all logs
	chdir_check(dirpath);
	while (entry = readdir(dirp)) {
		if (!strcmp("..", entry->d_name))
			continue;
		if (!strcmp(".", entry->d_name))
			continue;

		fd = open_check(entry->d_name, O_RDONLY);
		size = get_filelen(fd);

		read_check(fd, &strace_output[total_size], size);
		total_size += size;
		
		close(fd);
	}

	fchdir_check(dirfd);
	close(dirfd);
	closedir(dirp);

	return strace_output;
}

// Syscall wrapper functions:
static int fchdir_check(int fd)
{
	if (fchdir(fd) < 0) {
		fprintf(stderr, "Error: Cannot enter given directory\n%m\n");
		exit(3);
	}
}
static void chdir_check(const char *path)
{
	if (chdir(path) < 0) {
		fprintf(stderr, "Error: Cannot enter given directory\n%m\n");
		exit(3);
	}
}

static off_t lseek_check(int fd, off_t offset, int whence)
{
	off_t ret = lseek(fd, offset, whence);
	if (ret == -1) {
		fprintf(stderr, "Error: Cannot find the end of the file\n%m\n");
		exit(4);
	}
	return ret;
}

static int open_check(const char *path, int flags)
{
	int fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "Error: Cannot open file in the given directory\n%m\n");
		exit(5);
	}
	return fd;
}

static ssize_t read_check(int fd, void *buf, size_t count)
{
	ssize_t ret = read(fd, buf, count);
	if (ret < 0) {
		fprintf(stderr, "Error: Cannot read file in the given directory\n%m\n");
		exit(6);
	}
	return ret;
}
