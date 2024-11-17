#!/usr/bin/env python3

import base64
import subprocess
import os
import sys

def main():
    print("Enter the Base64-encoded .bmp file:\n", flush=True)
    base64_data = sys.stdin.readline().strip()

    try:
        binary_data = base64.b64decode(base64_data)
    except base64.binascii.Error as e:
        print(f"Error: Invalid Base64 input. {e}\n", flush=True)
        return

    image_filename = 'image.bmp'
    with open(image_filename, 'wb') as f:
        f.write(binary_data)
    print(f"Decoded image saved to {image_filename}\n", flush=True)

    print("Enter the message to hide in the image:\n", flush=True)
    message = sys.stdin.readline().strip()

    message_filename = 'message.txt'
    with open(message_filename, 'w') as f:
        f.write(message)
    print(f"Secret message saved to {message_filename}\n", flush=True)
    executable = './julekort'

    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        print(f"Error: Executable '{executable}' not found or not executable.\n", flush=True)
        return

    try:
        jule_process = subprocess.Popen(
            [executable,message_filename, image_filename, 'output.bmp'],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=subprocess.STDOUT, 
            close_fds=False
        )
        jule_process.communicate()
    except Exception as e:
        print(f"An error occurred while running the VM: {e}\n", flush=True)
    if jule_process.returncode != 0:
        print(f"Error: julekort exited with non-zero status {jule_process.returncode}.\n", flush=True)
        return
    
    try:
        stego_image = open('output.bmp', 'rb').read()
        b64_data = base64.b64encode(stego_image)
    except Exception as e:
        print(f"Error: Error opening generated image.\n", flush=True)
        return
    print(f"Result: {b64_data.decode()}", flush=True)
if __name__ == '__main__':
    main()
