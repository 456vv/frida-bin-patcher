package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type ExecutableFormat int

const (
	PE ExecutableFormat = iota
	MachO
	ELF
)

type Replacement struct {
	Old string `json:"old"`
	New string `json:"new"`
}

type Replacements struct {
	SectionName string         `json:"section_name"`
	Items       []*Replacement `json:"items"`
}

func describeArch(file interface{}, format ExecutableFormat) string {
	switch format {
	case MachO:
		switch f := file.(type) {
		case *macho.File:
			return describeMachOArch(f)
		case *macho.FatFile:
			return "MachO Fat Binary (Multiple Architectures)"
		}
	case ELF:
		if f, ok := file.(*elf.File); ok {
			return describeELFArch(f)
		}
	case PE:
		if f, ok := file.(*pe.File); ok {
			return describePEArch(f)
		}
	}
	return "Unknown Architecture"
}

func cpuTypeToString(cpu macho.Cpu) string {
	switch cpu {
	case macho.Cpu386:
		return "x86"
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuArm:
		return "ARM"
	case macho.CpuArm64:
		return "ARM64"
	case macho.CpuPpc:
		return "PowerPC"
	case macho.CpuPpc64:
		return "PowerPC 64"
	default:
		return fmt.Sprintf("Unknown CPU type: %d", cpu)
	}
}

func describeMachOArch(f *macho.File) string {
	cpu := cpuTypeToString(f.Cpu)
	byteOrder := "Little Endian"
	if f.ByteOrder == binary.BigEndian {
		byteOrder = "Big Endian"
	}
	return fmt.Sprintf("MachO: CPU: %s, Byte Order: %s, File Type: %s", cpu, byteOrder, f.Type.String())
}

func describeELFArch(f *elf.File) string {
	var details []string
	details = append(details, fmt.Sprintf("Machine: %s", f.Machine.String()))
	details = append(details, fmt.Sprintf("Class: %s", f.Class.String()))
	details = append(details, fmt.Sprintf("Data: %s", f.Data.String()))
	details = append(details, fmt.Sprintf("OSABI: %s", describeOSABI(f.OSABI)))
	details = append(details, fmt.Sprintf("ABI Version: %d", f.ABIVersion))
	details = append(details, fmt.Sprintf("Type: %s", f.Type.String()))
	details = append(details, fmt.Sprintf("Entry: 0x%x", f.Entry))
	if len(f.Progs) > 0 {
		details = append(details, fmt.Sprintf("Program Headers: %d", len(f.Progs)))
		for _, prog := range f.Progs {
			details = append(details, fmt.Sprintf("  Type: %s, Flags: %s, VAddr: 0x%x, Memsz: 0x%x",
				prog.Type.String(), describeProgramFlags(prog.Flags), prog.Vaddr, prog.Memsz))
		}
	}
	if len(f.Sections) > 0 {
		details = append(details, fmt.Sprintf("Section Headers: %d", len(f.Sections)))
		for _, section := range f.Sections {
			details = append(details, fmt.Sprintf("  Name: %s, Type: %s, Flags: %s, Addr: 0x%x, Size: 0x%x",
				section.Name, section.Type.String(), describeSectionFlags(section.Flags), section.Addr, section.Size))
		}
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		details = append(details, fmt.Sprintf("Dynamic Symbols: %d", len(syms)))
	}
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		details = append(details, fmt.Sprintf("Imported Libraries: %s", strings.Join(libs, ", ")))
	}
	return strings.Join(details, "\n")
}

func describeOSABI(osabi elf.OSABI) string {
	switch osabi {
	case elf.ELFOSABI_NONE:
		return "UNIX System V ABI"
	case elf.ELFOSABI_HPUX:
		return "HP-UX"
	case elf.ELFOSABI_NETBSD:
		return "NetBSD"
	case elf.ELFOSABI_LINUX:
		return "Linux"
	case elf.ELFOSABI_SOLARIS:
		return "Sun Solaris"
	case elf.ELFOSABI_AIX:
		return "IBM AIX"
	case elf.ELFOSABI_IRIX:
		return "SGI Irix"
	case elf.ELFOSABI_FREEBSD:
		return "FreeBSD"
	case elf.ELFOSABI_TRU64:
		return "Compaq TRU64 UNIX"
	case elf.ELFOSABI_MODESTO:
		return "Novell Modesto"
	case elf.ELFOSABI_OPENBSD:
		return "OpenBSD"
	case elf.ELFOSABI_ARM:
		return "ARM"
	case elf.ELFOSABI_STANDALONE:
		return "Standalone (embedded) application"
	default:
		return fmt.Sprintf("Unknown OSABI (%d)", osabi)
	}
}

func describeProgramFlags(flags elf.ProgFlag) string {
	var s []string
	if flags&elf.PF_X != 0 {
		s = append(s, "X")
	}
	if flags&elf.PF_W != 0 {
		s = append(s, "W")
	}
	if flags&elf.PF_R != 0 {
		s = append(s, "R")
	}
	return strings.Join(s, "+")
}

func describeSectionFlags(flags elf.SectionFlag) string {
	var s []string
	if flags&elf.SHF_WRITE != 0 {
		s = append(s, "W")
	}
	if flags&elf.SHF_ALLOC != 0 {
		s = append(s, "A")
	}
	if flags&elf.SHF_EXECINSTR != 0 {
		s = append(s, "X")
	}
	return strings.Join(s, "+")
}

func describePEArch(f *pe.File) string {
	var details []string
	details = append(details, fmt.Sprintf("Machine: %d", f.Machine))
	characteristics := describeCharacteristics(f.Characteristics)
	if len(characteristics) > 0 {
		details = append(details, fmt.Sprintf("Characteristics: %s", strings.Join(characteristics, "\n")))
	}
	if f.OptionalHeader != nil {
		switch oh := f.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			details = append(details, "Format: PE32")
			details = append(details, fmt.Sprintf("Subsystem: %s", describeSubsystem(oh.Subsystem)))
			details = append(details, fmt.Sprintf("BaseOfCode: 0x%X", oh.BaseOfCode))
			details = append(details, fmt.Sprintf("BaseOfData: 0x%X", oh.BaseOfData))
		case *pe.OptionalHeader64:
			details = append(details, "Format: PE32+")
			details = append(details, fmt.Sprintf("Subsystem: %s", describeSubsystem(oh.Subsystem)))
			details = append(details, fmt.Sprintf("BaseOfCode: 0x%X", oh.BaseOfCode))
		}
	}
	details = append(details, fmt.Sprintf("Number of Sections: %d", len(f.Sections)))

	for i, s := range f.Sections {
		details = append(details, fmt.Sprintf("\tSection %d: %s", i, describePESection(s)))
	}
	details = append(details, fmt.Sprintf("Number of Symbols: %d", len(f.Symbols)))

	return strings.Join(details, "\n")
}

func describePESection(s *pe.Section) string {
	return fmt.Sprintf("Name: %s, Address: 0x%X, Size: 0x%X", s.Name, s.VirtualAddress, s.Size)
}

func describeCharacteristics(characteristics uint16) []string {
	var chars []string
	if characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
		chars = append(chars, "Executable")
	}
	if characteristics&pe.IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 {
		chars = append(chars, "Large Address Aware")
	}
	if characteristics&pe.IMAGE_FILE_DLL != 0 {
		chars = append(chars, "DLL")
	}
	if characteristics&pe.IMAGE_FILE_32BIT_MACHINE != 0 {
		chars = append(chars, "32-bit")
	}
	if characteristics&pe.IMAGE_FILE_SYSTEM != 0 {
		chars = append(chars, "System")
	}
	if characteristics&pe.IMAGE_FILE_DEBUG_STRIPPED != 0 {
		chars = append(chars, "Debug Stripped")
	}
	return chars
}

func describeSubsystem(subsystem uint16) string {
	switch subsystem {
	case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		return "Windows GUI"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		return "Windows Console"
	case pe.IMAGE_SUBSYSTEM_EFI_APPLICATION:
		return "EFI Application"
	case pe.IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		return "EFI Boot Service Driver"
	case pe.IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		return "EFI Runtime Driver"
	case pe.IMAGE_SUBSYSTEM_NATIVE:
		return "Native"
	case pe.IMAGE_SUBSYSTEM_POSIX_CUI:
		return "POSIX Console"
	default:
		return fmt.Sprintf("Unknown (%d)", subsystem)
	}
}

var (
	fseed   = flag.Int64("seed", 1659, "frida版本号")
	finput  = flag.String("input", "", "输入二进制文件")
	ffilter = flag.String("filter", "", "过滤配置文件")
	foutput = flag.String("output", "", "二进制文件输出")
)

func main() {
	flag.Parse()
	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return
	}

	// 首先复制输入文件到输出文件
	if err := copyFile(*finput, *foutput); err != nil {
		fmt.Println("Error copying file:", err)
		os.Exit(1)
	}

	file, format, err := detectAndOpenFile(*foutput)
	if err != nil {
		fmt.Println("Error opening file:", err)
		os.Exit(1)
	}

	fmt.Println("Detected file format:", format)
	fmt.Println(describeArch(file, format))

	switch f := file.(type) {
	case *macho.File:
		handleSignleArchitecture(f, *foutput, *ffilter, format)
	case *macho.FatFile:
		handleMultipleArchitectures(f, *foutput, *ffilter, format)
	case *elf.File:
		handleELFFile(f, *foutput, *ffilter, format)
	case *pe.File:
		handlePEFile(f, *foutput, *ffilter, format)
	default:
		fmt.Println("Unsupported file type")
		os.Exit(1)
	}

	fmt.Println("Patch success")
}

func detectAndOpenFile(filePath string) (interface{}, ExecutableFormat, error) {
	if machoFile, err := macho.Open(filePath); err == nil {
		return machoFile, MachO, nil
	}
	if fatFile, err := macho.OpenFat(filePath); err == nil {
		return fatFile, MachO, nil
	}
	if elfFile, err := elf.Open(filePath); err == nil {
		return elfFile, ELF, nil
	}
	if peFile, err := pe.Open(filePath); err == nil {
		return peFile, PE, nil
	}
	return nil, 0, fmt.Errorf("unsupported file format")
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)

	os.Chmod(dst, 0o755)
	return err
}

func handlePEFile(file *pe.File, output, filter string, format ExecutableFormat) {
	replacementsList, err := buildReplacements(filter)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, replacements := range replacementsList {
		section := file.Section(replacements.SectionName)
		if section == nil {
			fmt.Printf("Warning: %s section not found in file\n", replacements.SectionName)
			continue
		}
		data, err := section.Data()
		if err != nil {
			fmt.Printf("Error reading section data for %s: %v\n", replacements.SectionName, err)
			continue
		}
		modifiedData := replaceInSection(section.Name, data, replacements.Items)
		if err := writeModifiedSection(output, int64(section.Offset), modifiedData); err != nil {
			fmt.Printf("Error writing modified data for %s: %v\n", replacements.SectionName, err)
			continue
		}
		fmt.Printf("Successfully patched %s section\n", replacements.SectionName)
	}
}

func handleELFFile(file *elf.File, output, filter string, format ExecutableFormat) {
	replacementsList, err := buildReplacements(filter)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, replacements := range replacementsList {
		section := file.Section(replacements.SectionName)
		if section == nil {
			fmt.Printf("Warning: %s section not found in file\n", replacements.SectionName)
			continue
		}
		data, err := section.Data()
		if err != nil {
			fmt.Printf("Error reading section data for %s: %v\n", replacements.SectionName, err)
			continue
		}
		modifiedData := replaceInSection(section.Name, data, replacements.Items)
		if err := writeModifiedSection(output, int64(section.Offset), modifiedData); err != nil {
			fmt.Printf("Error writing modified data for %s: %v\n", replacements.SectionName, err)
			continue
		}
		fmt.Printf("Successfully patched %s section\n", replacements.SectionName)
	}
}

func handleSignleArchitecture(file *macho.File, output, filter string, format ExecutableFormat) {
	replacementsList, _ := buildReplacements(filter)
	for _, replacements := range replacementsList {
		section := file.Section(replacements.SectionName)
		if section == nil {
			fmt.Printf("Warning: %s section not found in file\n", replacements.SectionName)
			continue
		}
		data, err := section.Data()
		if err != nil {
			fmt.Printf("Error reading section data for %s: %v\n", replacements.SectionName, err)
			continue
		}
		modifiedData := replaceInSection(section.Name, data, replacements.Items)
		if err := writeModifiedSection(output, int64(section.Offset), modifiedData); err != nil {
			fmt.Printf("Error writing modified data for %s: %v\n", replacements.SectionName, err)
			continue
		}
		fmt.Printf("Successfully patched %s section\n", replacements.SectionName)
	}
}

func handleMultipleArchitectures(fatFile *macho.FatFile, filePath, filter string, format ExecutableFormat) {
	for _, arch := range fatFile.Arches {
		patchArchitecture(arch, filePath, filter, format)
	}
}

func patchArchitecture(arch macho.FatArch, filePath, filter string, format ExecutableFormat) {
	replacementsList, err := buildReplacements(filter)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, replacements := range replacementsList {
		section := arch.Section(replacements.SectionName)
		if section == nil {
			fmt.Printf("Warning: %s section not found in architecture %s\n", replacements.SectionName, arch.Cpu.String())
			continue
		}
		data, err := section.Data()
		if err != nil {
			fmt.Printf("Error reading section data for %s in architecture %s: %v\n", replacements.SectionName, arch.Cpu.String(), err)
			continue
		}
		modifiedData := replaceInSection(section.Name, data, replacements.Items)
		if err := writeModifiedSection(filePath, int64(arch.Offset+section.Offset), modifiedData); err != nil {
			fmt.Printf("Error writing modified data for %s in architecture %s: %v\n", replacements.SectionName, arch.Cpu.String(), err)
			continue
		}
		fmt.Printf("Successfully patched %s section\n", replacements.SectionName)
	}
}

func isStringAlpha(s string) bool {
	for _, c := range s {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func buildReplacements(filter string) ([]Replacements, error) {
	var filterNewFile string
	if strings.HasSuffix(filter, ".json") {
		filterNewFile = filter
	}
	fb, err := os.ReadFile(filterNewFile)
	if err != nil {
		return nil, err
	}
	var rem []Replacements
	if err := json.Unmarshal(fb, &rem); err != nil {
		return nil, err
	}
	return rem, nil
}

func generateRandomString(length int, seed int64, charSet string) string {
	l := len(charSet)
	var result string
	rng := NewSimpleLCG(seed)
	for range length {
		k := int(rng.Next() * float64(l))
		result += string(charSet[k])
	}
	return result
}

func replaceInSection(name string, data []byte, replacements []*Replacement) []byte {
	modifiedData := make([]byte, len(data))
	copy(modifiedData, data)
	modifiedDataLen := len(modifiedData)

	counter := 0
	for _, replacement := range replacements {
		regx := regexp.MustCompile(`#R(\d+)`)
		replacement.New = regx.ReplaceAllStringFunc(replacement.New, func(a string) string {
			l, _ := strconv.Atoi(a[2:])
			return generateRandomString(l, *fseed, charSet)
		})

		oldBytes := []byte(replacement.Old)
		newBytes := []byte(replacement.New)
		var err error

		if strings.HasPrefix(replacement.Old, "base64:") {
			oldBytes, err = base64.StdEncoding.DecodeString(replacement.Old[7:])
			if err != nil {
				fmt.Printf("(%s) parse error %v", replacement.Old, err)
				continue
			}
		}
		if strings.HasPrefix(replacement.New, "base64:") {
			newBytes, err = base64.StdEncoding.DecodeString(replacement.New[7:])
			if err != nil {
				fmt.Printf("(%s) parse error %v", replacement.New, err)
				continue
			}
		}

		for i := 0; i <= len(modifiedData)-len(oldBytes); i++ {
			if bytesEqual(modifiedData[i:i+len(oldBytes)], oldBytes) {
				index_start := (i - 20)
				if index_start < 0 {
					index_start = 0
				}
				index_end := (i + 20) + len(oldBytes)
				if index_end > modifiedDataLen {
					index_end = modifiedDataLen
				}
				fmt.Printf("[*] patching: %s section: %s offset: %#x with: %s find: %s\n", oldBytes, name, i, newBytes, modifiedData[index_start:index_end])

				replacement := make([]byte, len(oldBytes))
				copy(replacement, newBytes)
				for j := len(newBytes); j < len(oldBytes); j++ {
					replacement[j] = 0
				}
				copy(modifiedData[i:i+len(oldBytes)], replacement)
				counter++
			}
		}
	}

	fmt.Printf("Replaced %d occurrences\n", counter)

	return modifiedData
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeModifiedSection(filePath string, offset int64, data []byte) error {
	f, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteAt(data, offset)
	return err
}

type SimpleLCG struct {
	m, a, c, state int64
}

func NewSimpleLCG(seed int64) *SimpleLCG {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &SimpleLCG{
		m:     4294967296, // 2^32
		a:     1664525,
		c:     1013904223,
		state: seed,
	}
}

func (lcg *SimpleLCG) Next() float64 {
	lcg.state = (lcg.a*lcg.state + lcg.c) % lcg.m
	return float64(lcg.state) / float64(lcg.m)
}
