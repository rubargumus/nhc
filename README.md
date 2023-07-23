# SHA Hash Cracker

SHA Hash Cracker is a Python script that allows you to crack MD5, SHA-1, SHA-256, SHA-512, and MD4 hash values using a wordlist.

## Features

- Crack a single hash value
- Crack multiple hash values from a file
- Utilize multiple CPU cores for parallel processing

## Getting Started

### Prerequisites

- Python 3.x

### Installation

1. Clone the repository:

git clone https://github.com/rubargumus/nhc.git
cd your_repository_name

2. Install the required packages:

pip install -r requirements.txt


## Usage

### Crack a Single Hash Value

To crack a single hash value, use the following command:

python main.py wordlist.txt <hash_type> -hv <hash_value>


Replace `wordlist.txt` with the path to your wordlist file, `<hash_type>` with the type of hash to crack (`md5`, `sha1`, `sha256`, `sha512`, or `md4`), and `<hash_value>` with the hash value to crack.

### Crack Multiple Hash Values

To crack multiple hash values from a file, use the following command:

python main.py wordlist.txt <hash_type> -f <hash_file> -p <num_processes>


Replace `wordlist.txt` with the path to your wordlist file, `<hash_type>` with the type of hash to crack (`md5`, `sha1`, `sha256`, `sha512`, or `md4`), `<hash_file>` with the path to the file containing multiple hash values (one per line), and `<num_processes>` with the number of parallel processes to use (defaults to all CPU cores).

## Examples

Here are some usage examples:

python main.py wordlist.txt md5 -hv 098f6bcd4621d373cade4e832627b4f6
python main.py wordlist.txt sha256 -f hashes.txt -p 4


## License

This project is licensed under the [MIT License](LICENSE).
