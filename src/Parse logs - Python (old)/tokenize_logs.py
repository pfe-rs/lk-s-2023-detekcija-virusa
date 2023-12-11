#!/bin/python
import os
import ctypes
import re
import pickle
import threading

libreadlogs = ctypes.CDLL("./libtokenize.so")
libreadlogs.read_strace_log.argtypes = [ctypes.c_char_p]
libreadlogs.read_strace_log.restype = ctypes.c_char_p

libreadlogs.parse_strace_line.argtypes = [ctypes.c_char_p]
libreadlogs.parse_strace_line.restype = ctypes.c_char_p

libreadlogs.get_selinux_context.argtypes = [ctypes.c_char_p]
libreadlogs.get_selinux_context.restype = ctypes.c_char_p

def read_strace_log(filepath:str):
	result = libreadlogs.read_strace_log(filepath.encode())
	return result.decode()

def filter_log(strace_output:str):
	# Match rows with "resumed"
	pattern_resumed = re.compile(r'^.*resumed.*$', re.MULTILINE)
	# Match pids along with the braces []
	pattern_pid = re.compile(r'\[pid\s+\d+\] ')
	# Match lines starting with "strace: Process"
	pattern_strace_process = re.compile(r'.*strace: Process.*', re.MULTILINE)
	# Match lines ending with "+++" or "---"
	pattern_plus_minus = re.compile(r'.*(\+\+\+|\-\-\-)$', re.MULTILINE)
	# Match lines with syscall format - syscall_name(...)...
	pattern_syscall = re.compile(r'^\w+\(.*\).*', re.MULTILINE)

	strace_output = pattern_resumed.sub('', strace_output)
	strace_output = pattern_pid.sub('', strace_output)
	strace_output = pattern_strace_process.sub('', strace_output)
	strace_output = pattern_plus_minus.sub('', strace_output)
	strace_output = pattern_syscall.findall(strace_output)
	strace_output = '\n'.join(strace_output)

	# Remove blank lines - str.strip() removes blank chars from beginning and end of the string
	return '\n'.join([line for line in strace_output.splitlines() if line.strip()])

def get_selinux_type(filepath):
	selinux_context = libreadlogs.get_selinux_context(filepath.encode())
	selinux_context = selinux_context.decode()
	if selinux_context == "":
		parent_dir = os.path.dirname(filepath)
		return get_selinux_type(parent_dir)

	selinux_type = selinux_context.split(':')[2]
	return selinux_type
	
def tokenize_program(filepath:str):
	strace_log = read_strace_log(filepath)
	strace_log = filter_log(strace_log)
	tokenized_program = []
	for line in strace_log.splitlines():
		tokenized_line = []
		# Remove everything past the last equal sign and replace excess chars (like , . ( ) ') with whitespace
		line = line.rsplit('=', 1)[0]
		result = libreadlogs.parse_strace_line(line.encode('utf-8')).decode()

		# Fetch SELinux context for file paths
		tokens = result.split()
		for i in range(len(tokens)):
			if tokens[i].startswith('/'):
				tokens[i] = get_selinux_type(tokens[i])
			tokenized_line.append(tokens[i])

		tokenized_program.append(tokenized_line)

	return tokenized_program

def thread_work(file_list, start_index, end_index):
	tid = threading.get_ident()
	tokenized_log = []
	for i in range(start_index, end_index+1):
		tokenized_log.append(tokenize_program(file_list[i]))
		progress = progress + 1
		print(f"Processed {progress} files")

# Load additional data for training Word2Vec
os.chdir("/home/marko/malware_logs_filtered")
file_list = os.listdir(".")

tokenized_log = []
progress = 0
	
print("Finished loading logs")

with open("/home/marko/tokenized_log_malware.pkl", "wb") as f:
	pickle.dump(tokenized_log, f)
