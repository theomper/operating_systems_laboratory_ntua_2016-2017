#!/usr/bin/env python

import sys
import os

# fun that creates the path for a cgroup of an application
# if the path already exists, the fun returns does nothing
def create_proc(proc_command):
	monitor = proc_command[1]
	task = proc_command[3]
	path = "/sys/fs/cgroup/cpu/"+monitor+"/"+task
	if os.path.exists(path):
		return
	else:
		os.makedirs(path)

# fun to delete the cgroup of an application
# if the path doe not exists, the fun returns does nothing
def remove_proc(proc_command):
	monitor = proc_command[1]
	task = proc_command[3]
	path = "/sys/fs/cgroup/cpu/"+monitor+"/"+task
	if not os.path.exists(path):
		return
	else:
		os.removedirs(path)

# fun that adjusts the cpu.shares value for the cgroup of an application
# if the path doe not exists, the fun returns does nothing
def set_limit_proc(proc_command):
	monitor = proc_command[1]
	task = proc_command[3]
	cpu_shares = proc_command[5]
	path = "/sys/fs/cgroup/cpu/"+monitor+"/"+task+"/cpu.shares"
	if os.path.exists(path):
		f = open(path, "w")
		f.write(cpu_shares)
		f.close
	else:
		return

# fun that adds a process ID into the cgroup's tasks of an application
# if the path doe not exists, the fun returns does nothing
def add_proc(proc_command):
	monitor = proc_command[1]
	task = proc_command[3]
	pid = proc_command[4]
	path = "/sys/fs/cgroup/cpu/"+monitor+"/"+task+"/tasks"
	if os.path.exists(path):
		f = open(path, "a")
		f.write(pid)
		f.close
	else:
		return

# main fun for reading line by line input and calling the selected procedure
def limit():
	diction = {"create":create_proc, "remove":remove_proc, "set_limit":set_limit_proc, "add":add_proc}

	for line in sys.stdin:

		proc_command = line.rstrip().split(":")
		print proc_command[0]
		proc = diction[proc_command[0]] #we assume that the input is always correct
		proc(proc_command)

if __name__ == '__main__':
	limit()