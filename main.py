import hashlib
import sys
import multiprocessing
import argparse

ascii = """                                    
\033[31m          ,--.                ,--,                                  \033[0m
\033[31m        ,--.'|              ,--.'|          ,----..                 \033[0m
\033[31m    ,--,:  : |           ,--,  | :         /   /   \                \033[0m
\033[31m ,`--.'`|  ' :        ,---.'|  : '        |   :     :               \033[0m
\033[31m |   :  :  | |        |   | : _' |        .   |  ;. /               \033[0m
\033[31m :   |   \ | :        :   : |.'  |        .   ; /--`                \033[0m
\033[31m |   : '  '; |        |   ' '  ; :        ;   | ;                   \033[0m     
\033[31m '   ' ;.    ;        '   |  .'. |        |   : |                   \033[0m
\033[31m |   | | \   |        |   | :  | '        .   | '___                \033[0m
\033[31m '   : |  ; .'        '   : |  : ;        '   ; : .'|               \033[0m
\033[31m |   | '`--'          |   | '  ,/         '   | '/  :               \033[0m
\033[31m '   : |              ;   : ;--'          |   :    /                \033[0m
\033[31m ;   |.'              |   ,/               \   \ .'                 \033[0m
\033[31m '---'                '---'                 `---`                   \033[0m
"""                                                  
print(ascii)


def check_hash(wordlist, hash_type, hash_value):
    try:
        for word in wordlist:
            word = word.strip()

            if hash_type == "md5":
                hashed_word = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == "sha1":
                hashed_word = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type == "sha256":
                hashed_word = hashlib.sha256(word.encode()).hexdigest()
            elif hash_type == "sha512":
                hashed_word = hashlib.sha512(word.encode()).hexdigest()
            elif hash_type == "md4":
                hashed_word = hashlib.new('md4', word.encode()).hexdigest()

            if hashed_word == hash_value:
                return word

    except Exception as e:
        print(f"Error occurred: {e}")
        return None

    return None

def crack_hash_parallel(wordlist_file, hash_type, hash_values, process_count):
    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as wordlist:
            pool = multiprocessing.Pool(processes=process_count)

            chunk_size = 10000
            results = []

            for hash_value in hash_values:
                while True:
                    chunk = [wordlist.readline().strip() for _ in range(chunk_size)]
                    if not chunk[0]:
                        break
                    result = pool.apply_async(check_hash, (chunk, hash_type, hash_value))
                    results.append((result, hash_value))

            pool.close()
            pool.join()

            found_hashes = set()
            for result, hash_value in results:
                word = result.get()
                if word:
                    found_hashes.add(hash_value)
                    print(f"RESULT ==> Hash: {hash_value}, Word: {word}")

            for hash_value in hash_values:
                if hash_value not in found_hashes:
                    print(f"RESULT ==> Hash: {hash_value}, Word: Not found.")

    except Exception as e:
        print(f"Error occurred: {e}")

def crack_single_hash(wordlist_file, hash_type, hash_value, process_count):
    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as wordlist:
            pool = multiprocessing.Pool(processes=process_count)

            chunk_size = 10000
            results = []

            while True:
                chunk = [wordlist.readline().strip() for _ in range(chunk_size)]
                if not chunk[0]:
                    break
                result = pool.apply_async(check_hash, (chunk, hash_type, hash_value))
                results.append(result)

            pool.close()
            pool.join()

            for result in results:
                word = result.get()
                if word:
                    print(f"RESULT ==> Hash: {hash_value}, Word: {word}")
                    break
            else:
                print(f"RESULT ==> Hash: {hash_value}, Word: Not found.")

    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NUKE Hash Cracker")
    parser.add_argument("wordlist_file", help="Path to the wordlist file containing the words to be used for cracking the hash values")
    parser.add_argument("hash_type", choices=["md5", "sha1", "sha256", "sha512", "md4"], help="Type of hash to crack (md5, sha1, sha256, sha512, md4)")
    parser.add_argument("-f", "--hash-file", dest="hash_file", help="Path to the file containing multiple hash values to be cracked")
    parser.add_argument("-p", "--processes", type=int, help="Number of parallel processes to use (defaults to all CPU cores)")
    parser.add_argument("-hv", "--hash-value", dest="hash_value", help="A single hash value to be cracked (optional)")

    example_text = '''Examples:
        python main.py wordlist.txt md5 -hv 098f6bcd4621d373cade4e832627b4f6
        --OR--

        python main.py wordlist.txt sha256 -f hashes.txt -p 4
    '''

    parser.epilog = example_text

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    max_processes = multiprocessing.cpu_count()
    if args.processes is not None:
        if args.processes < 1:
            print("Error: You must specify at least 1 process.")
            sys.exit(1)
        elif args.processes > max_processes:
            print(f"Warning: The specified number of processes exceeds the maximum CPU core count ({max_processes}). Automatically using {max_processes} processes.")
            args.processes = max_processes
    else:
        args.processes = max_processes

    if not (args.hash_value or args.hash_file):
        print("Error: You must specify either a single hash value to crack or a file containing multiple hash values.")
        sys.exit(1)

    if args.hash_value:
        crack_single_hash(args.wordlist_file, args.hash_type, args.hash_value, args.processes)
    else:
        with open(args.hash_file, "r", encoding="utf-8", errors="ignore") as hash_file:
            hash_values = [line.strip() for line in hash_file]
        if not hash_values:
            print("Error: The hash file is empty.")
            sys.exit(1)
        crack_hash_parallel(args.wordlist_file, args.hash_type, hash_values, args.processes)
