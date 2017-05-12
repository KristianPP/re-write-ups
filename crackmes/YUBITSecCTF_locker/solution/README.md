# YUBITSecCTF_locker solution

## Approach 1 - Self-BF

The program is modified when loaded in memory from the debugger in such a way
that it literally brute-force itself until a solution is reached.

## Commands

```bash
r2 -i ./bf_passwd.r2 ./locker
```

### Description

This current algorithm is more than convinient for this kind of abuse.
There are two main modifications made:

1. Change the initialization of 'int password = 0' to incrementation.
This is done after we have passed with the debugger the point of initialization.
1. Change the exit of the function to return us to the modified password init.
This way we make the 'main()' function one giant loop that has no exit

Other modifications made are just a few NOPs that clear out unneeded interaction/output
functions performance wise.

We put a breakpoint on the eax getting the password integer. Then we run the program and wait like 2 min.