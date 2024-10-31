import time
import lief
import random
import os
import sys
import json
import string

class Patcher:
    ELF_MAGIC_MAIN = "7F 45 4C 46 "
    exclusions = ["_frida"]

    @staticmethod
    def load_json_as_map(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data
        except FileNotFoundError:
            print(f"Error: File not found: {filepath}")
            return None
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None

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
        return "".join(random.sample(string.ascii_lowercase+string.ascii_uppercase, length))

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
    def initiate_patching_process(self, path, outpath):
        with open(path, 'rb') as f:
            binary = bytearray(f.read())
            
        try:
            self.exclusions.append(binary.index(b'/System/Library/Caches/') + len('/System'))
        except:
            pass
        
        current_directory = os.path.dirname(os.path.abspath(__file__))
        frida_strings_to_patch = self.load_json_as_map(current_directory+"/filter.json")

        for key, val in frida_strings_to_patch.items():
            if key != val:
                if val == "" :
                    val = self.generate_name(len(key))
                self.do_patch(self, binary, key, val)
                time.sleep(0.2)

        with open(outpath, 'wb') as f:
            f.write(binary)

        print(f"[*] modified binary has been saved to: {outpath}")