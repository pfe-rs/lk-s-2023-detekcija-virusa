#ifndef LIBRARY_H
#define LIBRARY_H
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>

#define check(function)							\
	if((function) < 0)						\
	{								\
		fprintf(stderr, #function);				\
		fprintf(stderr, " Failed: %i\n", errno);		\
		fflush(stderr);						\
		syscall(SYS_exit_group, 1);				\
	}
#define printerr(...)							\
	fprintf(stderr, __VA_ARGS__);					\
	fflush(stderr);

#endif
