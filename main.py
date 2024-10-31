import sys
sys.path.append("..")

import argparse
import os
from patchagent import Patcher
from pathlib import Path

class Main:
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--input', type=str, nargs='?', help='location of frida binary to patch (server or gadget)')
    parser.add_argument('-o','--output', type=str, default="", help='output location for new binary')
    parser.add_argument('-v','--verify', action="store_true", help='enable verification')
    parser.add_argument('-s','--seed', type=int, default=1, help='random seed')
    parser.add_argument('-r','--recover',action="store_true", help='recover')

    args = parser.parse_args()

    def handle(args, input, output):
        if output == "":
            output = input+".bak"
            
            if os.path.exists(output) == False:
                os.rename(input, output)
                output_ = output
                output = input
                input = output_
            if os.path.exists(output):
                os.remove(input)
                output_ = output
                output = input
                input = output_

        patcher = Patcher()
        if patcher.check_path(input):
            patcher.initiate_patching_process(patcher, input, output, args.seed)

        if args.verify:
            Patcher.verify_patched_binary(patcher, output)

    if os.path.isdir(args.input):
        
        if args.recover:
            for input in Path(args.input).rglob("*.bak"): # rglob 递归遍历所有文件和目录
                if input.is_file():
                    input = f"{input}"
                    output = os.path.splitext(input)[0]
                    if os.path.exists(output):
                        os.remove(output)
                    os.rename(input, output)
        else:
            for input in Path(args.input).rglob("*"): # rglob 递归遍历所有文件和目录
                if input.is_file():
                    if os.path.splitext(input)[1] != ".bak":
                        handle(args, f"{input}", args.output)
           
    else:
        if args.recover:
            backfile = args.input+".bak"
            if os.path.exists(backfile):
                os.remove(args.input)
                os.rename(backfile, args.input)
        else:
            handle(args, args.input, args.output)
    