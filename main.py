import argparse
import parse
from os import path

if __name__ == "__main__":

    p = argparse.ArgumentParser()
    p.add_argument("file", type=str, help="name/path of the input file")
    p.add_argument("-x", action="store_true", help="extract and parse PCAP file")
    p.add_argument("-n", action="store", help="specify minimum string length")
    args = p.parse_args()

    if path.exists(args.file):
        if not path.isfile(args.file):
            raise Exception("Given path is not a file!")
    else:
        raise Exception("Given path does not exist!")

    if args.x:
        extracted = []
        if args.n:
            extracted = parse.extract_passwords(args.file, N=int(args.n))
        else:
            extracted = parse.extract_passwords(args.file)
        print("Extracted Passwords: " + str(extracted))
