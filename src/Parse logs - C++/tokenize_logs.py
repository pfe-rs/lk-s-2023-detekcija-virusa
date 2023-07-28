#!/bin/python
import pickle
import ctypes
import subprocess

libsocket = ctypes.CDLL("./libsocket.so")

disconnect = libsocket.disconnect_sock
disconnect.argtypes = []
disconnect.restype = None

connect = libsocket.connect_sock
connect.argtypes = []
connect.restype = None

read_next = libsocket.read_next
read_next.argtypes = []
read_next.restype = ctypes.c_char_p;

program_break_ptr = ctypes.pointer(ctypes.c_int.in_dll(libsocket, "program_break"))
line_break_ptr = ctypes.pointer(ctypes.c_int.in_dll(libsocket, "line_break"))

subprocess.Popen(["./tokenize", "/home/marko/malware_logs_filtered", "8"])
tokenized_log = []
program_log = []
line = []

connect()
i = 0
while True:
	ret = read_next().decode()
	if ret == "" and program_break_ptr.contents.value == 0 and line_break_ptr.contents.value == 0:
		break
	if ret == "" and line_break_ptr.contents.value == 1:
		line_break_ptr.contents.value = 0;
		program_log.append(line)
		line = []
		continue
	if ret == "" and program_break_ptr.contents.value == 1:
		program_break_ptr.contents.value = 0;
		tokenized_log.append(program_log)
		program_log = []
		i = i + 1
		print(f"Collected program {i}")
		continue

	line.append(ret)

disconnect()

with open("tokens_malware.pkl", "wb") as f:
	pickle.dump(tokenized_log, f)

print("Finished")