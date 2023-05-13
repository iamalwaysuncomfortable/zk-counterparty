import sys
from aleo_python import hash_int

def hash_integer(integer):
    return hash_int(integer)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            input_integer = int(sys.argv[1])
            hashed_integer = hash_integer(input_integer)
            print(f"The hash of {input_integer} is {hashed_integer}.")
        except ValueError:
            print("Invalid input. Please provide an integer.")
    else:
        print("Please provide an integer as a command line argument.")
