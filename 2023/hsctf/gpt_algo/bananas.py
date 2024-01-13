from pwn import *

p = remote("banana-queries.hsctf.com", 1337)

def find_max_subarray_length(N, bananas):
    cum_sum = [0] * (N + 1)  # Cumulative sum array
    cum_sum[0] = 0

    # Calculate cumulative sum
    for i in range(1, N + 1):
        cum_sum[i] = cum_sum[i - 1] + bananas[i - 1]

    max_length = 0  # Maximum subarray length

    # Iterate over all possible subarray lengths
    for subarray_len in range(1, N + 1):
        # Iterate over all possible starting indices
        for start in range(N - subarray_len + 1):
            # Calculate the sum of the current subarray
            subarray_sum = cum_sum[start + subarray_len] - cum_sum[start]

            # Check if the sum is divisible by the subarray length
            if subarray_sum % subarray_len == 0:
                max_length = max(max_length, subarray_len)

    return max_length


# Read input
N = int(p.recvline().decode())
bananas = list(map(int, p.recvline().decode().split()))

# Find the size of the biggest subarray of days
max_subarray_length = find_max_subarray_length(N, bananas)

# Output the result
p.recvline()
p.sendline(str(max_subarray_length).encode())
p.interactive()