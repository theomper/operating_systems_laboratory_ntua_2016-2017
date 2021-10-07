#!/usr/bin/env python

import sys
import os

# reading input line by line
# splitting and storing applications' names and cpu usage
# computing and printing cpu's workload
# printing applications' names and cpu usage
def policy():
	Available = 2000
	Percentage = 1
	app_name_l = []
	for line in sys.stdin:
		name = line.rstrip()
		app_name = name.split(":")[1]
		value = int(name.split(":")[3])
		Available -= value
		Percentage = Available/2000.0 
		app_name_l.append((app_name,value))	
	print ('score:'+str(Percentage))
	for (app_name, value) in app_name_l:	
		print ('set_limit:'+app_name+':cpu.shares:'+str(value))

if __name__ == '__main__':
	policy()