# Optimized_RSA

This is a repository that implements a custom bignum class to run optimized RSA 
encryption and decryption using C++ (and uses CUDA multithreading for optimized
performance). 

To use this RSA program, first fill in the values for the `rsa_n`, `rsa_e`, and `rsa_d`
keys in the `bignum.cpp` file. Ensure the numbers are written within the double quotes (they must be strings). Then, run the required C++ compilation and execution
commands. 

Compilation: `g++ -std=c++20 -Wall -O3 bignum.cpp main.cpp -o bignum`

Execution: The executable is stored in a file called `bignum`. The encrypt command is 
`e` and decrypt command is `d`. The input can be passed in either from the command line
or as a .txt file (the execution commands differ for the two methods).

