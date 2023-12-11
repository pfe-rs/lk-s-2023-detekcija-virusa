#!/bin/python
import re
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import use
import pickle
import ctypes

fig_width = 1366
fig_height = 768

libreadlogs = ctypes.CDLL("/home/marko/libreadlogs.so")
libreadlogs.read_strace_log.argtypes = [ctypes.c_char_p]
libreadlogs.read_strace_log.restype = ctypes.c_char_p

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

def parse_strace_output(strace_output:str):
	syscall_pattern = re.compile(r'^(\w+)\((.*?)\)\s+=\s+(-?\w+)')
	syscalls = []
	for line in strace_output.splitlines():
		match = syscall_pattern.match(line)
		if match:
			syscall_name = match.group(1)
			syscalls.append(syscall_name)
	return syscalls

def generate_syscall_set(syscalls:str):
	syscall_names = {}

	# Create mapping between syscall names and indices
	for i, syscall in enumerate(syscalls):
		if syscall not in syscall_names:
			syscall_names[syscall] = len(syscall_names)

	return syscall_names

def generate_matrix_graph(syscalls:str, syscall_names):
	num_syscalls = len(syscall_names)
	matrix_graph = np.zeros((num_syscalls, num_syscalls), dtype=int)
	for i in range(len(syscalls) - 1):
		curr_syscall_i, next_syscall_i = syscall_names[syscalls[i]], syscall_names[syscalls[i + 1]]
		matrix_graph[curr_syscall_i][next_syscall_i] += 1

	return matrix_graph

def create_heatmap(matrix_graph, syscall_names):
	num_syscalls = len(syscall_names)

	use('QtAgg')
	fig, ax = plt.subplots(figsize=(fig_width//100, fig_height//100))
	im = ax.imshow(matrix_graph, cmap='viridis')
	ax.figure.colorbar(im, ax=ax)

	# Display syscall names as labels
	ax.set_xticks(np.arange(num_syscalls))
	ax.set_yticks(np.arange(num_syscalls))
	ax.set_xticklabels(syscall_names)
	ax.set_yticklabels(syscall_names)

	# Rotate the x-axis labels for better readability
	plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

	# Loop over data dimensions and create text annotations
	#for i in range(num_syscalls):
	#    for j in range(num_syscalls):
	#        ax.text(j, i, str(matrix[i, j]), ha="center", va="center", color="w")

	ax.set_title("Syscall Frequency Matrix")
	fig.tight_layout()
	
	plt.show()

def get_term_frequency(parsed_syscalls, term_frequency={}, max_occurrences=5000):
	for term, freq in term_frequency.items():
		term_frequency[term] = 0
	# Count the occurrences of each term in the list
	for term in parsed_syscalls:
		term_frequency[term] = term_frequency.get(term, 0) + 1

	for term, freq in term_frequency.items():
		if freq > max_occurrences:
			term_frequency[term] = max_occurrences

	return term_frequency

def create_histogram(term_frequency):
	terms = list(term_frequency.keys())
	freqs = list(term_frequency.values())

	total_syscalls = sum(freqs)
	for i in range(len(freqs)):
		freqs[i] = freqs[i] / total_syscalls

	# Create the histogram
	plt.figure(figsize=(10, 6))
	plt.bar(range(len(terms)), freqs)
	
	plt.xticks(range(len(terms)), terms, rotation=45, ha='right')
	
	plt.xlabel('Terms')
	plt.ylabel('Frequency (Normalized)')
	plt.title('Histogram of Terms Occurrence (Normalized)')
	plt.tight_layout()
	plt.show()

	return terms

def read_strace_log(dirpath:str):
	result = libreadlogs.read_strace_log(dirpath.encode())
	return result.decode()

###############################################################################

### Generate histograms from raw data and save data needed by both histograms and heatmaps ###
strace_output = read_strace_log("/home/marko/malware_logs_filtered")
strace_output = filter_log(strace_output)
strace_output = parse_strace_output(strace_output)
syscall_names = generate_syscall_set(strace_output)

strace_output_b = read_strace_log("/home/marko/benign_logs")
strace_output_b = filter_log(strace_output_b)
strace_output_b = parse_strace_output(strace_output_b)
syscall_names_b = generate_syscall_set(strace_output_b)

for term in syscall_names_b.keys():
	if term not in syscall_names:
		syscall_names[term] = len(syscall_names)

matrix_graph = generate_matrix_graph(strace_output, syscall_names)
matrix_graph_b = generate_matrix_graph(strace_output_b, syscall_names)

term_frequency = get_term_frequency(strace_output)
term_frequency_b = get_term_frequency(strace_output_b)

for term, freq in term_frequency_b.items():
	if term not in term_frequency.keys():
		term_frequency[term] = 0

term_frequency = get_term_frequency(strace_output, term_frequency)
term_frequency_b = get_term_frequency(strace_output_b, term_frequency)


#with open("data.pkl", "wb") as f:
#	terms = list(term_frequency.keys())
#	pickle.dump((terms, strace_output, matrix_graph, syscall_names), f)

#with open("data_benign.pkl", "wb") as f:
#	terms = list(term_frequency_b.keys())
#	pickle.dump((terms, strace_output_b, matrix_graph_b, syscall_names), f)



### Load previously saved data and generate histograms based on it ###
#with open("data.pkl", "rb") as f:
#	terms, _, matrix_graph, syscall_names = pickle.load(f)
#with open("data_benign.pkl", "rb") as f:
#	terms_b, _, matrix_graph_b, syscall_names_b = pickle.load(f)

#term_frequency = {}
#term_frequency_b = {}
#for term in terms_b:
#	term_frequency_b[term] = 0
#for term in terms:
#	term_frequency[term] = 0

#term_frequency = get_term_frequency(strace_output, term_frequency)
#term_frequency_b = get_term_frequency(strace_output_b, term_frequency_b)

#create_histogram(term_frequency_b)
#create_histogram(term_frequency)

### Load previously saved data and generate heatmaps based on it ###
#with open("data.pkl", "rb") as f:
#	terms, strace_output, matrix_graph, syscall_names = pickle.load(f)
#with open("data_benign.pkl", "rb") as f:
#	terms_b, strace_output_b, matrix_graph_b, syscall_names_b = pickle.load(f)

mask = matrix_graph > 5000
matrix_graph[mask] = 5000
mask = matrix_graph_b > 5000
matrix_graph_b[mask] = 5000

create_heatmap(matrix_graph, syscall_names)
create_heatmap(matrix_graph_b, syscall_names_b)
