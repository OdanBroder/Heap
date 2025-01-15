# Exploitation Techniques and Labs

This repository contains a collection of practical examples and resources for various heap exploitation techniques, demonstrating concepts like fastbin overflow, House-of-Force, House-of-Orange, Safe-unlink, and Unsafe-unlink. Each folder is dedicated to a specific exploitation technique and includes resources such as code, demos, documentation, and images for a deeper understanding.

## Directory Structure

### Book
- `HeapLab - GLIBC Heap Exploitation.pdf`: A PDF book that provides in-depth theory and examples for heap exploitation techniques in GLIBC.

### Fastbin-dup
- `FASTBIN_DUP.md`: Documentation explaining the fastbin duplication vulnerability.
- `README.md`: Overview and setup instructions for the Fastbin-dup exploit.
- `demo/`: Demo scripts or binaries for testing and showcasing the exploit.
- `fastbin_dup`: Core implementation of the fastbin duplication vulnerability exploit.
- `fastbin_dup_2`: Additional demo or exploit variations for fastbin duplication.
- `overwrite_target_1.py`: Python script for targeting a specific vulnerability in the heap.
- `shell_1.py`: Shellcode for exploiting the fastbin-dup vulnerability.
- `shell_2.py`: Alternative shellcode for the same exploit.

### House-of-Force
- `README.md`: Overview and setup instructions for the House-of-Force exploit.
- `demo/`: Demo scripts or binaries for testing and showcasing the exploit.
- `house_of_force`: Core implementation of the House-of-Force exploit.
- `overwrite_target.py`: Python script for targeting a specific vulnerability in the heap using House-of-Force.
- `shell.py`: Shellcode for exploiting the House-of-Force vulnerability.
- `solve.py`: Script for solving or automating part of the House-of-Force exploit.

### House-of-Orange
- `README.md`: Overview and setup instructions for the House-of-Orange exploit.
- `shell.py`: Shellcode for exploiting the House-of-Orange vulnerability.
- `template.py`: Template script for adapting the exploit.

### One-byte
- `README.md`: Overview and setup instructions for the One-byte exploit.
- `shell.py`: Shellcode for exploiting the One-byte vulnerability.
- `template.py`: Template script for adapting the exploit.

### Safe-unlink
- `README.md`: Overview and setup instructions for the Safe-unlink exploit.
- `Safe-unlink.md`: Documentation explaining the Safe-unlink vulnerability.
- `overwrite_target.py`: Python script for targeting a specific vulnerability in the heap using Safe-unlink.
- `safe_unlink`: Core implementation of the Safe-unlink exploit.
- `shell.py`: Shellcode for exploiting the Safe-unlink vulnerability.

### Unsafe-unlink
- `README.md`: Overview and setup instructions for the Unsafe-unlink exploit.
- `Unsafe-unlink.md`: Documentation explaining the Unsafe-unlink vulnerability.
- `demo/`: Demo scripts or binaries for testing and showcasing the exploit.
- `shell.py`: Shellcode for exploiting the Unsafe-unlink vulnerability.
- `unsafe_unlink`: Core implementation of the Unsafe-unlink exploit.

### images/
Contains various images used for demonstrating or explaining the techniques.

- `FastBin-Dup/`: Images related to the Fastbin-dup vulnerability.
- `House-of-Force/`: Images related to the House-of-Force vulnerability.
- `House-of-Orange/`: Images related to the House-of-Orange vulnerability.
- `One-Byte/`: Images related to the One-byte vulnerability.

## Setup Instructions

Each folder contains a `README.md` with detailed instructions for setting up and running the respective exploit.

1. Clone the repository to your local machine.
2. Navigate to the desired folder for the exploit you want to test.
3. Follow the instructions in the corresponding `README.md` for setting up and running the exploit.
4. Use the demo files and scripts to explore the vulnerability further.

## External Resources

- [Linux Heap Exploitation Part 1 (Udemy)](https://www.udemy.com/course/linux-heap-exploitation-part-1/): A comprehensive course on Linux heap exploitation, offering valuable insights into heap vulnerabilities and exploitation techniques.

## Contributing

Feel free to contribute to this repository by adding new exploits, improving existing ones, or providing documentation improvements. You can open a pull request with your changes.
---

This project is intended for educational purposes to demonstrate heap exploitation techniques and should only be used in a controlled and legal environment.

## Acknowledgements

A special thanks to the creators of the **Linux Heap Exploitation Part 1** course on Udemy for providing excellent foundational knowledge in heap exploitation techniques that helped shape this repository.
