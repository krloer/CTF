#!/usr/bin/env python3

import base64
import subprocess
import os
import sys

def main():
    print("Enter the Base64-encoded shellcode:\n")
    base64_data = sys.stdin.readline().strip()

    try:
        binary_data = base64.b64decode(base64_data)
    except base64.binascii.Error as e:
        print(f"Error: Invalid Base64 input. {e}\n")
        return

    output_filename = 'shellcode.bin'
    with open(output_filename, 'wb') as f:
        f.write(binary_data)
    print(f"Decoded binary saved to {output_filename}\n")

    vm_executable = './vm'

    if not os.path.isfile(vm_executable) or not os.access(vm_executable, os.X_OK):
        print(f"Error: VM executable '{vm_executable}' not found or not executable.\n")
        return

    try:
        vm_process = subprocess.Popen(
            [vm_executable, output_filename],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=subprocess.STDOUT, 
            close_fds=False
        )
        vm_process.communicate()
    except Exception as e:
        print(f"An error occurred while running the VM: {e}\n")
    
if __name__ == '__main__':
    main()
