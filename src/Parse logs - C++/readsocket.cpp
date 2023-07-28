#include <iostream>
#include <type_traits>
#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

using namespace std;

template <typename Func, typename... Args>
auto checkerr(Func&& function, const char *funcname, Args&&... args) -> decltype(function(forward<Args>(args)...)) {
	auto ret = function(forward<Args>(args)...);
	using ReturnType = decltype(function(forward<Args>(args)...));
	if constexpr (is_integral_v<ReturnType>)
		if (ret == -1) {
			char *out;
			asprintf(&out, "\n%s Failed: %m\nError code: %i", funcname, errno);
			throw std::runtime_error(string(out));
		}
	return ret;
}
#define check(function, ...) checkerr(function, #function, __VA_ARGS__)

// Global identifiers
extern "C" int line_break, program_break;
int line_break = 0, program_break = 0;
int fdsock;
char token[50];
char empty_string[] = "";
struct msghdr msg = { 0 };
struct iovec iov;

extern "C" void disconnect_sock()
{
	close(fdsock);
}

extern "C" void connect_sock()
{
	struct sockaddr_un addr;
	socklen_t bufsize = sizeof(struct sockaddr_un);
	int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "/tmp/socket");

	unlink("/tmp/socket");
	check( bind, fd, (struct sockaddr *) &addr, strlen(addr.sun_path) + sizeof(addr.sun_family) );
	check( listen, fd, 1 );
	fdsock = check( accept, fd, (struct sockaddr *) &addr, &bufsize );
	check( unlink, "/tmp/socket" );
	close(fd);

	// Set structures for future receives
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = token;
	iov.iov_len = 50;
}

extern "C" char *read_next()
{
	size_t ret = check( recvmsg, fdsock, &msg, 0 );
	if (ret == 0)
		return empty_string;
	if (token[0] == 0 && token[1] == 0) {
		line_break = 1;
		return empty_string;
	}
	if (token[0] == 0 && token[1] == 10) {
		program_break = 1;
		return empty_string;
	}
	return token;
}