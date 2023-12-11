#!/bin/python
import os
os.environ['KERAS_BACKEND'] = 'tensorflow'

import gensim
import numpy as np
import ctypes
import re
import subprocess
import pickle

libreadlogs = ctypes.CDLL("./libreadlogs.so")
libreadlogs.read_strace_log.argtypes = [ctypes.c_char_p]
libreadlogs.read_strace_log.restype = ctypes.c_char_p

libreadlogs.parse_strace_line.argtypes = [ctypes.c_char_p]
libreadlogs.parse_strace_line.restype = ctypes.c_char_p

def read_strace_log(dirpath:str):
	result = libreadlogs.read_strace_log(dirpath.encode())
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

def fetch_selinux_context(filepath):
	try:
		selinux_context = subprocess.check_output(['stat', '-c', '%C', filepath]).decode().strip()
		selinux_type = selinux_context.split(':')[2]
		return selinux_type
	except subprocess.CalledProcessError:
		parent_dir = os.path.dirname(filepath)
		if parent_dir == filepath:
			# Reached the root directory, return root_t
			return 'root_t'
		return fetch_selinux_context(parent_dir)

def get_tokens(dirpath:str):
	strace_log = read_strace_log(dirpath)
	strace_log = filter_log(strace_log)
	syscall_list = []
	for line in strace_log.splitlines():
		# Remove everything past the last equal sign
		line = line.rsplit('=', 1)[0]
		# Replace excess chars (like , . ( ) ') with whitespace
		result = libreadlogs.parse_strace_line(line.encode('utf-8')).decode()

	# Fetch SELinux context for file paths
	tokens = result.split()
	for i in range(len(tokens)):
		if tokens[i].startswith('/'):
			tokens[i] = fetch_selinux_context(tokens[i])

	syscall_list.append(tokens)

	return syscall_list

# Load additional data for training Word2Vec
sentences = get_tokens("benign_logs")
print("Finished loading logs")
with open("tokens_benign.pkl", "wb") as f:
	pickle.dump(sentences, f)

"""
# Load pre-trained GloVe embeddings
glove_path = "glove.840B.300d.txt"
glove_embeddings = {}
with open(glove_path, encoding="utf-8") as f:
	for line in f:
		values = line.strip().split()
		if len(values) != 301:
			continue
		word = values[0]
		vector = np.asarray(values[1:], dtype='float32')
		glove_embeddings[word] = vector
print("Finished loading pre-trained word embeddings")

# Train Word2Vec model
model = gensim.models.Word2Vec(sentences, size=300, window=5, min_count=1, sg=1, workers=4)

# Initialize Word2Vec model with GloVe embeddings
for word, vector in glove_embeddings.items():
	model.wv[word] = vector

# Train the model on additional data
print("Starting training")
model.train(sentences, total_examples=model.corpus_count, epochs=10)

# Save the model
print("Saving fine-tuned model")
model.save("word2vec_model")

# Later, you can load the model
# model = gensim.models.Word2Vec.load("word2vec_model")
"""
