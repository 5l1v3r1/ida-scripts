#!/usr/bin/env python
__date__       = "03.22.2018"
__author__     = "https://vxlab.info/"
__description__= "Script changes PEB fields like BeingDebugged"

####################################
FLG_HEAP_ENABLE_TAIL_CHECK   = 0x00000010
FLG_HEAP_ENABLE_FREE_CHECK   = 0x00000020
FLG_HEAP_VALIDATE_PARAMETERS = 0x00000040
HEAP_FLASG = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
####################################
OFFSET_PEB_BeingDebugged = 2
OFFSET_PEB32_NtGlobalFlag = 0x68
OFFSET_PEB64_NtGlobalFlag = 0xBC
OFFSET_PEB64_AFTER_PEB32 = 0x1000
OFFSET_TEB64_PEB_LINK = 0x60
OFFSET_TEB32_PEB_LINK = 0x30
####################################

def UnsetDwordFlag(addr, mask):
	Flags = Dword(addr)
	if Flags == BADADDR: return False
	NewFlags = Flags &~ mask;
	return PatchDbgByte(addr, NewFlags)

def GetSegStart(name):
	name = name.lower()
	for seg in Segments():
		if SegName(seg).lower() == name:
			return seg
	return False
	
def IsWow64():
	return GetSegStart('wow64.dll') is not False
		
def GetTEB(tid):
	name = "TIB[%08X]" % tid
	return GetSegStart(name)
		
def GetPEB():
	tid = idc.GetCurrentThreadId()
	TEB = GetTEB(tid)
	if not TEB:	return False
	peb_offset = OFFSET_TEB64_PEB_LINK if IsWow64() else OFFSET_TEB32_PEB_LINK
	peb_pointer = Dword(TEB+peb_offset)
	return peb_pointer
	
def GetPEB32():
	peb = GetPEB()
	if not peb:	return False
	peb_delta = OFFSET_PEB64_AFTER_PEB32 if IsWow64() else 0
	peb -= peb_delta
	return peb
 
def Hide_PEB32_IsDebugged(peb):
	FlagAddr = peb + OFFSET_PEB_BeingDebugged
	return PatchDbgByte(FlagAddr, 0)
	
def Hide_PEB32_NtGlobalFlag(peb):
	FlagAddr = peb + OFFSET_PEB32_NtGlobalFlag
	return UnsetDwordFlag(FlagAddr, HEAP_FLASG)
	
def HideDebuger_PEB():
	peb = GetPEB32()
	
	if peb is False:
		print 'Can\'t find PEB32 address'
		return

	if Hide_PEB32_IsDebugged(peb) is False:
		print 'Can\'t patch PEB32_IsDebugged'
		return
		
	if Hide_PEB32_NtGlobalFlag(peb) is False:
		print 'Can\'t patch NtGlobalFlag'
		return
	
	print '[PEB patched]'

if __name__ == "__main__":
	HideDebuger_PEB()