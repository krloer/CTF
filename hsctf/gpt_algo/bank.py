from pwn import *

p = remote("bank.hsctf.com", 1337)

# Read the number of trials
num_trials = 5

for _ in range(num_trials):
    # Read the number of accounts for the current trial
    n = int(p.recvline().decode().strip())

    # Create a list to store the time windows
    time_windows = []

    # Read n lines and store the time windows
    for _ in range(n):
        a, b = map(int, p.recvline().decode().split())
        time_windows.append((a, b))

    # Sort the time windows based on the end times
    time_windows.sort(key=lambda x: x[1])

    max_hacked_accounts = 0  # Maximum number of accounts that can be hacked
    current_time = 0  # Current time

    # Iterate over the time windows
    for window in time_windows:
        a, b = window

        # Check if the current time is less than or equal to the start time of the window
        if current_time <= a:
            max_hacked_accounts += 1
            current_time = max(current_time, a) + 10  # Update the current time

    # Output the maximum number of accounts that can be hacked
    p.sendline(str(max_hacked_accounts).encode())
    print(max_hacked_accounts)
    # p.interactive()

p.interactive()