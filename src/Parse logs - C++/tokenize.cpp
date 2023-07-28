#include <iostream>
#include <vector>
#include <regex>
#include <string>
#include <filesystem>
#include <sstream>
#include <type_traits>
#include <cctype>
#include <thread>
#include <mutex>
#include <utility>

#include <cstring>
#include <cstdio>
#include <cerrno>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <selinux/selinux.h>
#include <fcntl.h>

using namespace std;
namespace fs = filesystem;

template <typename Func, typename... Args>
auto checkerr(Func&& function, const char *funcname, Args&&... args) -> decltype(function(forward<Args>(args)...)) {
	auto ret = function(forward<Args>(args)...);
	using ReturnType = decltype(function(forward<Args>(args)...));
	if constexpr (is_integral_v<ReturnType>)
		if (ret == -1) {
			char *out;
			asprintf(&out, "\n%s Failed: %m\nError code: %i", funcname, errno);
			throw runtime_error(string(out));
		}

	return ret;
}
#define check(function, ...) checkerr(function, #function, __VA_ARGS__)

// Returns vector with strings representing each syscall line
static vector<string> filter_log(string strace_output) {
	// Remove rows with "resumed"
	// Remove pids along with the braces []
	// Remove lines starting with "strace: Process"
	// Remove lines ending with "+++" or "---"
	regex pattern_resumed(R"(^.*resumed.*$)", regex_constants::multiline);
	regex pattern_pid(R"(\[pid\s+\d+\] )");
	regex pattern_strace_process(R"(.*strace: Process.*)", regex_constants::multiline);
	regex pattern_plus_minus(R"(.*(\+\+\+|\-\-\-)$)", regex_constants::multiline);
	regex pattern_syscall(R"(^\w+\(.*\).*)", regex_constants::multiline);

	strace_output = regex_replace(strace_output, pattern_resumed, "");
	strace_output = regex_replace(strace_output, pattern_pid, "");
	strace_output = regex_replace(strace_output, pattern_strace_process, "");
	strace_output = regex_replace(strace_output, pattern_plus_minus, "");

	// Match lines with syscall format - syscall_name(...)... and add only them to the vector syscall_lines
	vector<string> syscall_lines;
	sregex_iterator it(strace_output.begin(), strace_output.end(), pattern_syscall);
	sregex_iterator end;
	while (it != end) {
		syscall_lines.push_back(it->str());
		++it;
	}

	return syscall_lines;
}

thread_local char *selinux_context = NULL;
static string get_selinux_context(const string &path)
{
	int ret;

	if (selinux_context) {
		freecon(selinux_context);
		selinux_context = NULL;
	}
	ret = getfilecon(path.c_str(), &selinux_context);
	if (ret < 0)
		return "";

	return string(selinux_context);
}

static string get_selinux_type(const string &path)
{
	string context = get_selinux_context(path);
	if (context == "") {
		string parent_dir = fs::path(path).parent_path().string();
		return get_selinux_type(parent_dir);
	}

	// user_u:role_r:type_t:s0 - get type - third token with ':' as delimiter
	istringstream iss(context);
	string token;
	for(int i = 0; i < 3; i++)
		getline(iss, token, ':');

	return token;
}

static void parse_strace_line(string &line)
{
	size_t i, len;
	bool escape = false, in_string = false, delete_hex = false;

	for(i = 0; i < line.size(); i++) {
		// Skip string literals, but remove "" around them
		if (line[i] == '\\' && !escape && in_string) {
			escape = true;
			continue;
		}
		if (escape) {
			escape = false;
			continue;
		}
		if (line[i] == '\"') {
			in_string = !in_string;
			line[i] = ' ';
			continue;
		}
		if (in_string)
			continue;

		// Detect hex number and mark it's removal
		if (i < len-1)
			if (line[i] == '0' && line[i+1] == 'x')
				delete_hex = true;

		// Keep certain chars
		if (isalpha(line[i]) && !delete_hex)
			continue;
		if (line[i] == '_' || line[i] == '=')
			continue;
		// Because next condition will keep them, remove explicitly numbers after = sign, like st_size=2
		if (isdigit(line[i]))
			if (i - 1 >= 0)
				if (line[i-1] == '=') {
					line[i] = ' ';
					line[i-1] = ' ';
					continue;
				}
		// Keep digits surrounded by chars at least 2 indexes away
		// Required for tokens like pread64
		if (isdigit(line[i]) && !delete_hex) {
			if (i - 1 >= 0)
				if (isalpha(line[i-1]))
					continue;
			if (i - 2 >= 0)
				if (isalpha(line[i-2]) && line[i-1] != ' ')
					continue;
			if (i + 1 < line.size())
				if (isalpha(line[i+1]))
					continue;
			if (i + 2 < line.size())
				if (isalpha(line[i+2]) && line[i+1] != ' ')
					continue;
		}

		// If this is the end of the token, end deleting letters from previous hex number
		if (line[i] == ' ')
			delete_hex = false;

		// Replace everything else with whitespace
		line[i] = ' ';
	}
}

static string read_strace_log(const string &filepath)
{
	int fd;
	string s;

	fd = check( open, filepath.c_str(), O_RDONLY );
	auto len = check( lseek, fd, 0, SEEK_END );
	check( lseek, fd, 0, SEEK_SET );
	s.resize(len+1);
	check( read, fd, &s[0], len );
	close(fd);

	return s;
}

static vector<vector<string>> tokenize_program(string filepath)
{
	string strace_output = read_strace_log(filepath);
	vector<string> syscall_lines = filter_log(strace_output);
	vector<vector<string>> tokenized_program;

	for (string &line : syscall_lines) {
		vector<string> tokenized_line;
		// Remove everything past the last equal sign and replace excess chars (like , . ( ) ') with whitespace
		auto pos = line.find_last_of('=');
		if (pos != string::npos)
			line.erase(pos);
		parse_strace_line(line);
		
		istringstream iss(line);
		string token;
		while(getline(iss, token, ' ')) {
			auto firstNonSpace = token.find_first_not_of(" \t\n\v\f\r");
			if (firstNonSpace == string::npos)
				continue;

			if (token[0] == '/')
				token = get_selinux_type(token);
			tokenized_line.push_back(token);
			
			// Skip the actual data from certain syscalls
			if (token == "read" || token == "pread" || token == "pread64" || token == "write" || token == "recvfrom" ||
			token == "pwrite" || token == "pwrite64" || token == "getrandom" || token == "sendto")
				break;
		}

		tokenized_program.push_back(tokenized_line);
		tokenized_line.clear();
	}

	return tokenized_program;
}

vector<vector<vector<string>>> tokenized_log;
unsigned int processed = 0;
vector<string> paths;
mutex mut;

template <typename T>
vector<pair<size_t, size_t>> divide_vector(const vector<T> &myVector, size_t numParts) {
	vector<pair<size_t, size_t>> parts;
	size_t totalSize = myVector.size();
	size_t partSize = totalSize / numParts;
	size_t remainder = totalSize % numParts;

	size_t currentStart = 0;
	for (size_t i = 0; i < numParts; ++i) {
		size_t currentEnd = currentStart + partSize - 1;
		if (i < remainder)
			currentEnd++;	// Distribute the remainder among the first few parts

		parts.push_back(make_pair(currentStart, currentEnd));
		currentStart = currentEnd + 1;
	}

	return parts;
}

void thread_work(size_t start, size_t stop)
{
	pid_t tid = gettid();
	for(size_t i = start; i <= stop; i++) {
		auto tokenized_program = tokenize_program(paths[i]);
		mut.lock();
		tokenized_log.push_back(tokenized_program);
		cout << "Thread " << tid << " processed " << ++processed << ". file" << endl;
		mut.unlock();
	}
	cout << "Thread " << tid << " completed!" << endl;
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		cerr << "Wrong arguments! Pass path to the log directory and the number of worker threads." << endl;
		exit(1);
	}
	
	for (const auto &entry : fs::directory_iterator(argv[1]))
		if (fs::is_regular_file(entry))
			paths.push_back(entry.path().string());

	vector<thread> threads;
	int thread_num = stoi(argv[2]);
	auto ranges = divide_vector(paths, thread_num);
	for (int i = 0; i < thread_num; i++)
		threads.push_back(thread(thread_work, ranges[i].first, ranges[i].second));
	for (int i = 0; i < thread_num; i++)
		threads[i].join();

	// Send the result of calculation over Unix socket
	cout << "Finished processing! Sending results..." << endl;
	int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	struct sockaddr_un addr;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "/tmp/socket");
	check( connect, fd, (struct sockaddr *) &addr, strlen(addr.sun_path) + sizeof(addr.sun_family) );
	
	struct msghdr msg = { 0 };
	struct iovec iov;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	char boundary[2] = {0, 0};

	for (auto program : tokenized_log) {
		for (auto line : program) {
			for (auto token : line) {
				iov.iov_base = (void *) token.c_str();
				iov.iov_len = token.size()+1;
				check( sendmsg, fd, &msg, 0 );
			}
			boundary[1] = 0;
			iov.iov_base = boundary;
			iov.iov_len = 2;
			check( sendmsg, fd, &msg, 0 );
		}
		boundary[1] = 10;
		iov.iov_base = boundary;
		iov.iov_len = 2;
		check( sendmsg, fd, &msg, 0 );
	}

	close(fd);
	return 0;
}