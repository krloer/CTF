allowed = set("1<rjhniocd()_'[]+yremlsp,. ")

# target command:
#'"".join(open("flag.txt"))'


# Find some banned letters using globals
f = "dir(dir)[len('1<jhnoc()_[]+yremlsp,. ')][1+1+1+1+1]"
a = "dir()[1<1][1+1]"
g = "dir(())[1+1][(1+1)<<(1+1)]"
t = "dir()[1][1+1+1+1+1+1]"
x = "dir(())[len('eeeeeeeeeeeeeeeeeeeeeeeee')][1+1+1+1+1+1+1+1+1+1]"


# The string "flag.txt"
flagtxt = "+".join([f, "'l'", a, g, "'.'", t, x, t])

# The command that gets the flag content
readflag = "''.join(open(" + flagtxt + "))"
# This actually returns the content, but without surrounding quotes, and not stripped for newlines
# To actualyy use/print the flag, we need to quote it using triplequotes
triplequote = "''' ' '''[1]+''' ' '''[1]+''' ' '''[1]"

# Wrap thecommand in a print statement
cmd = "'prin'+"+t+"+'('+"+triplequote+"+"+ readflag + "+"+triplequote+ "+')'"
# cmd = "'prin'+"+t+"+'(" + "readflag" + ")'"

print("COMMAND:")
print(cmd)


print("\nDIFF:")
# Print all (if any) characters that are not allowed
print(set(cmd) - allowed)
# Print all (if any) characters that are missing
print(allowed - set(cmd))


print("\nEVAL:")
print(eval(cmd))

print("\nRESULT:")
exec(eval(cmd))
