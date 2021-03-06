// Code generated by 'go generate'; DO NOT EDIT.

package syscalls

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modDbgHelp  = windows.NewLazySystemDLL("DbgHelp.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procMiniDumpWriteDump                 = modDbgHelp.NewProc("MiniDumpWriteDump")
	procImpersonateLoggedOnUser           = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	procCreateProcessW                    = modkernel32.NewProc("CreateProcessW")
	procCreateRemoteThread                = modkernel32.NewProc("CreateRemoteThread")
	procCreateThread                      = modkernel32.NewProc("CreateThread")
	procDeleteProcThreadAttributeList     = modkernel32.NewProc("DeleteProcThreadAttributeList")
	procGetExitCodeThread                 = modkernel32.NewProc("GetExitCodeThread")
	procGetProcessHeap                    = modkernel32.NewProc("GetProcessHeap")
	procHeapAlloc                         = modkernel32.NewProc("HeapAlloc")
	procHeapFree                          = modkernel32.NewProc("HeapFree")
	procInitializeProcThreadAttributeList = modkernel32.NewProc("InitializeProcThreadAttributeList")
	procQueueUserAPC                      = modkernel32.NewProc("QueueUserAPC")
	procUpdateProcThreadAttribute         = modkernel32.NewProc("UpdateProcThreadAttribute")
	procVirtualAllocEx                    = modkernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx                  = modkernel32.NewProc("VirtualProtectEx")
	procWriteProcessMemory                = modkernel32.NewProc("WriteProcessMemory")
)

func MiniDumpWriteDump(hProcess windows.Handle, pid uint32, hFile uintptr, dumpType uint32, exceptionParam uintptr, userStreamParam uintptr, callbackParam uintptr) (err error) {
	r1, _, e1 := syscall.Syscall9(procMiniDumpWriteDump.Addr(), 7, uintptr(hProcess), uintptr(pid), uintptr(hFile), uintptr(dumpType), uintptr(exceptionParam), uintptr(userStreamParam), uintptr(callbackParam), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ImpersonateLoggedOnUser(hToken windows.Token) (err error) {
	r1, _, e1 := syscall.Syscall(procImpersonateLoggedOnUser.Addr(), 1, uintptr(hToken), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateProcess(appName *uint16, commandLine *uint16, procSecurity *windows.SecurityAttributes, threadSecurity *windows.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *StartupInfoEx, outProcInfo *windows.ProcessInformation) (err error) {
	var _p0 uint32
	if inheritHandles {
		_p0 = 1
	}
	r1, _, e1 := syscall.Syscall12(procCreateProcessW.Addr(), 10, uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(commandLine)), uintptr(unsafe.Pointer(procSecurity)), uintptr(unsafe.Pointer(threadSecurity)), uintptr(_p0), uintptr(creationFlags), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(currentDir)), uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(outProcInfo)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateRemoteThread(hProcess windows.Handle, lpThreadAttributes *windows.SecurityAttributes, dwStackSize uint32, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (threadHandle windows.Handle, err error) {
	r0, _, e1 := syscall.Syscall9(procCreateRemoteThread.Addr(), 7, uintptr(hProcess), uintptr(unsafe.Pointer(lpThreadAttributes)), uintptr(dwStackSize), uintptr(lpStartAddress), uintptr(lpParameter), uintptr(dwCreationFlags), uintptr(unsafe.Pointer(lpThreadId)), 0, 0)
	threadHandle = windows.Handle(r0)
	if threadHandle == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateThread(lpThreadAttributes *windows.SecurityAttributes, dwStackSize uint32, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (threadHandle windows.Handle, err error) {
	r0, _, e1 := syscall.Syscall6(procCreateThread.Addr(), 6, uintptr(unsafe.Pointer(lpThreadAttributes)), uintptr(dwStackSize), uintptr(lpStartAddress), uintptr(lpParameter), uintptr(dwCreationFlags), uintptr(unsafe.Pointer(lpThreadId)))
	threadHandle = windows.Handle(r0)
	if threadHandle == 0 {
		err = errnoErr(e1)
	}
	return
}

func DeleteProcThreadAttributeList(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST) {
	syscall.Syscall(procDeleteProcThreadAttributeList.Addr(), 1, uintptr(unsafe.Pointer(lpAttributeList)), 0, 0)
	return
}

func GetExitCodeThread(hTread windows.Handle, lpExitCode *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetExitCodeThread.Addr(), 2, uintptr(hTread), uintptr(unsafe.Pointer(lpExitCode)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetProcessHeap() (procHeap windows.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procGetProcessHeap.Addr(), 0, 0, 0, 0)
	procHeap = windows.Handle(r0)
	if procHeap == 0 {
		err = errnoErr(e1)
	}
	return
}

func HeapAlloc(hHeap windows.Handle, dwFlags uint32, dwBytes uintptr) (lpMem uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procHeapAlloc.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(dwBytes))
	lpMem = uintptr(r0)
	if lpMem == 0 {
		err = errnoErr(e1)
	}
	return
}

func HeapFree(hHeap windows.Handle, dwFlags uint32, lpMem uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procHeapFree.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(lpMem))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func InitializeProcThreadAttributeList(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST, dwAttributeCount uint32, dwFlags uint32, lpSize *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procInitializeProcThreadAttributeList.Addr(), 4, uintptr(unsafe.Pointer(lpAttributeList)), uintptr(dwAttributeCount), uintptr(dwFlags), uintptr(unsafe.Pointer(lpSize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func QueueUserAPC(pfnAPC uintptr, hThread windows.Handle, dwData uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procQueueUserAPC.Addr(), 3, uintptr(pfnAPC), uintptr(hThread), uintptr(dwData))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func UpdateProcThreadAttribute(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST, dwFlags uint32, attribute uintptr, lpValue *uintptr, cbSize uintptr, lpPreviousValue uintptr, lpReturnSize *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall9(procUpdateProcThreadAttribute.Addr(), 7, uintptr(unsafe.Pointer(lpAttributeList)), uintptr(dwFlags), uintptr(attribute), uintptr(unsafe.Pointer(lpValue)), uintptr(cbSize), uintptr(lpPreviousValue), uintptr(unsafe.Pointer(lpReturnSize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (addr uintptr, err error) {
	r0, _, e1 := syscall.Syscall6(procVirtualAllocEx.Addr(), 5, uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flAllocationType), uintptr(flProtect), 0)
	addr = uintptr(r0)
	if addr == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualProtectEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flNewProtect uint32, lpflOldProtect *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procVirtualProtectEx.Addr(), 5, uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}
