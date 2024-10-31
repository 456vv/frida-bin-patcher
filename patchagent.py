import time
import lief
import random
import os
import sys

class Patcher:
    ELF_MAGIC_MAIN = "7F 45 4C 46 "
    exclusions = ["_frida"]

    @staticmethod
    def verify_patched_binary(self, path):
        print ("\n[*] validating patched binary at: " + path)

        if lief.is_elf(path):
            bin = lief.parse(path)
        elif lief.is_macho(path):
            print("[!] Mach-O/iOS binary verification is not supported yet")
            sys.exit(1)
        else:
            print("[!] binary verification is only present in ELF formats")
            sys.exit(1)

        bin_segments = bin.segments
        bin_sections = bin.sections

        header = bin.header
        print ("[*] detected segments:", len(bin_segments))
        print ("[*] detected sections:", len(bin_sections))

        if len(bin_segments) != header.numberof_segments:
            print ("[!] segment mismatch detected!!: " + path)
            return -1
        
        if len(bin_sections) != header.numberof_sections:
            print ("[!] section mismatch detected!!: " + path)
            return -1

        print ("[*] section & segment verification completed")
        print ("[*] verifying magic")
        magic_header_id_bytes = header.identity
        magic = ""

        for x in range(4):
            byte_magic = str(hex(magic_header_id_bytes[x]))
            magic += byte_magic.upper()[2:] + " "

        if self.ELF_MAGIC_MAIN != magic:
            print ("[!] ELF magic mismatch detected, binary is corrupted!!")
            return -1

        print ("[*] ELF magic: ", magic)
        print ("[*] binary verification successful")

        return 0

    @staticmethod
    def generate_name(length):
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def do_patch(self, binary, replacer, replacee="", startpos = 0, endpos = 0):
        match = replacer.encode('utf8')
        length = len(match)
        if replacee == '':
            val = self.generate_name(length).encode('utf8')[startpos:]
        else:
            val = replacee.encode('utf8')[startpos:]
            if len(val) > length:
                raise Exception('[!] input length is higher than required')
            else:
                val += int.to_bytes(0, length - len(val), 'big')     
        if endpos > 0:
            val = val[:-endpos]
        cur_index = 0

        while True:
            try:
                index = binary.index(match, cur_index)
                cur_index = index + 1
                range =binary[index - 10 : 10 + index + length]
                pos = -1
                for key in self.exclusions:
                    pos = range.find(key.encode('utf8'))
                    if pos >= 0:
                        break
                if pos >= 0:
                    continue
                print("[*] patching: " + replacer + " at: " + str(hex(index)) + " with: " + val.decode("utf8")+ " range: " + str(range.decode("utf-8")))
                binary[index + startpos : index + length - endpos] = val
            except:
                break
                

    @staticmethod
    def check_path(binarypath):
        if os.path.exists(binarypath):
            return True
        return False
        
    @staticmethod
    def initiate_patching_process(self, path, outpath, seed):
        with open(path, 'rb') as f:
            binary = bytearray(f.read())
            
        try:
            self.exclusions.append(binary.index(b'/System/Library/Caches/') + len('/System'))
        except:
            pass

        frida_strings_to_patch = {
            "linjector":"",
            "gmain":"",
            "gum-js":"",
            "gdbus":"gdbus",
            "frida-gum":"",
            "frida-helper":"",
            "frida-agent":"",
            "frida-gadget":"",
            "pool-frida":"",
            "frida:rpc":"ABCDE:rpc",
            "\"frida\"":"\"ABCDE\"",
        }

        random.seed(seed)
        for key in frida_strings_to_patch.keys():
            val = frida_strings_to_patch.get(key)
            if key != val:
                if val == "" :
                    val = self.generate_name(len(key))
                self.do_patch(self, binary, key, val)
                time.sleep(0.2)

        with open(outpath, 'wb') as f:
            f.write(binary)

        print(f"[*] modified binary has been saved to: {outpath}")