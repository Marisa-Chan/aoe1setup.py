#!/usr/bin/python

import sys
import os
import re
import io
import shutil

dryrun = False

class Res:
	ID = ""
	sz = 0
	off = 0
	Type = ""
	cp = 0

class PEFile:
	Handle = None
	Sections = None
	ResTypes = None
	PlainRes = None


class PESection:
	VAddr = 0
	VSize = 0
	Addr = 0
	Size = 0
	Name = ""


class ResData:
	rva = 0
	sz = 0
	codepage = 0
	reserved = 0

def read4int(fl):
	return int.from_bytes( fl.read(4) , byteorder='little' )

def read2int(fl):
	return int.from_bytes( fl.read(2) , byteorder='little' )

def ReadName(fl):
	namesz = read2int(fl)
	return fl.read(namesz * 2).decode("UTF-16LE")

def ReadData(fl):
	dat = ResData()
	dat.rva = read4int(fl)
	dat.sz = read4int(fl)
	dat.codepage = read4int(fl)
	dat.reserved = read4int(fl)
	return dat

def ReadDir(pf, rsrc, TPNAME, lvl, rid):
	if lvl > 2:
		print("Err level")
		return
	pf.Handle.seek(12, 1)
	nmd = read2int(pf.Handle)
	ids = read2int(pf.Handle)
	
	named = list()
	idslst = list()
	
	for i in range(nmd):
		a = read4int(pf.Handle)
		b = read4int(pf.Handle)
		named.append( (a, b) )
	
	for i in range(ids):
		a = read4int(pf.Handle)
		b = read4int(pf.Handle)
		idslst.append( (a, b) )
	
	datlst = list()
	dirlst = list()
	
	for nm in named:
		pf.Handle.seek(rsrc.Addr + (nm[0] & 0x7FFFFFFF))
		TPN = ReadName(pf.Handle)
		adr = nm[1] & 0x7FFFFFFF
		
		if ( (nm[1] & (1 << 31)) ):
			dirlst.append( (TPN, rsrc.Addr + adr) )
		else:
			datlst.append( (TPN, rsrc.Addr + adr) )
		
	for nm in idslst:
		TPN = str(nm[0] & 0x7FFFFFFF)
		adr = nm[1] & 0x7FFFFFFF
		
		if ( (nm[1] & (1 << 31)) ):
			dirlst.append( (TPN, rsrc.Addr + adr) )
		else:
			datlst.append( (TPN, rsrc.Addr + adr) )

	for dat in datlst:
		pf.Handle.seek( dat[1] )
		d = ReadData(pf.Handle)
		r = Res()
		r.ID = dat[0]
		r.off = rsrc.Addr - rsrc.VAddr + d.rva
		r.sz = d.sz
		r.cp = d.codepage
		if (lvl == 0):
			r.Type = r.ID
			pf.PlainRes.append(r)
		elif (lvl == 1):
			if (not TPNAME in pf.ResTypes):
				pf.ResTypes[TPNAME] = dict()
				pf.ResTypes[TPNAME][r.ID + "_"] = list()
			
			r.Type = TPNAME
			pf.ResTypes[TPNAME][r.ID].append(r)
			
		elif (lvl == 2):
			r.Type = TPNAME
			pf.ResTypes[TPNAME][rid].append(r)
			
		
	for dr in dirlst:
		pf.Handle.seek( dr[1] )
		if (lvl == 0):
			ReadDir(pf, rsrc, dr[0], lvl + 1, 0)
		elif (lvl == 1):
			if (not TPNAME in pf.ResTypes):
				pf.ResTypes[TPNAME] = dict()
			if (not dr[0] in pf.ResTypes[TPNAME]):
				pf.ResTypes[TPNAME][ dr[0] ] = list()
			
			ReadDir(pf, rsrc, TPNAME, lvl + 1, dr[0])


def ReadPE(fl):
	pf = PEFile()
	pf.Sections = dict()
	pf.Handle = fl
	pf.ResTypes = dict()
	pf.PlainRes = list()
	
	fl.seek(0)
	if fl.read(2) != b'MZ':
		return False
	
	fl.seek(0x3C) #e_lfanew
	PE_POS = read4int(fl)
	
	fl.seek(PE_POS)
	if read4int(fl) != 0x4550:
		return False
	
	fl.seek(PE_POS + 6) #sec Numb
	secNumb = read2int(fl)
	
	i = 0
	while i < secNumb:
		fl.seek(PE_POS + 0xF8 + i * 0x28) #sections
		name = fl.read(8)
		pes = PESection()
		pes.VSize = read4int(fl)
		pes.VAddr = read4int(fl)
		pes.Size  = read4int(fl)
		pes.Addr  = read4int(fl)
		pes.Name = name.decode("ascii", errors='ignore').strip('\x00')
		
		pf.Sections[pes.Name] = pes
		
		i += 1
	
	
	if ".rsrc" in pf.Sections:
	
		rsrc = pf.Sections[".rsrc"]
		fl.seek(rsrc.Addr)
		
		ReadDir(pf, rsrc, "", 0, 0)
	
	return pf




def GetCMDData(pf, cid):
	r = pe.ResTypes["COMMANDDATA"][str(cid)][0]
	pf.Handle.seek(r.off)
	return pf.Handle.read(r.sz)

def ParseCStr(dat):
	s = ""
	for i in range(len(dat)):
		if dat[i] == 0:
			return (dat[i + 1:], s)
		else:
			s += chr( dat[i] )
	return (bytearray(), s)

def ScanTree(path, outdict, tree, lvlmax):
	for e in os.scandir(path):
		if e.is_dir() and lvlmax:
			ScanTree(e.path, outdict, ("{:s}{:s}/".format(tree, e.name)).lower(), lvlmax - 1)
		else:
			outdict[ ("{:s}{:s}".format(tree, e.name)).lower() ] = e.path
			#print(("{:s}{:s}".format(tree, e.name)).lower())

def DstPath(path, strdict):
	path = path.replace("%APPPATH\\", "")
	m = re.search("(%STRING([0-9]+))", path)
	if m:
		path = path.replace(m[1], strdict[ 500 + int(m[2])] )
	
	path = path.replace("\\", "/").lower()
	
	return path
	


##### main:
if len(sys.argv) < 3:
	print("Usage: python3 getlocale.py setuppath(AoE1/AoE1RoR) outpath")
	exit(0)

fileList = dict()
ScanTree(sys.argv[1], fileList, "", 10)

setup = None
enudll = None

if "aoesetup.exe" in fileList:
	setup = fileList["aoesetup.exe"]

if not setup and "aoeinst.exe" in fileList:
	setup = fileList["aoeinst.exe"]

if not setup and "aocsetup.exe" in fileList:
	setup = fileList["aocsetup.exe"]

if not setup:
	print("No setup.exe in the path")
	exit(1)

if "setupenu.dll" in fileList:
	enudll = fileList["setupenu.dll"]

if not enudll and "setupexp.dll" in fileList:
	enudll = fileList["setupexp.dll"]

if not enudll and "stpenux.dll" in fileList:
	enudll = fileList["stpenux.dll"]

if not enudll:
	print("No setupenu dll in the path")
	exit(1)

print(setup, enudll)
	
f = open(setup, "rb")
pe = ReadPE(f)

fd = open(enudll, "rb")
dll = ReadPE(fd)

strID = dict()

#Strings
for (rid, rlst) in dll.ResTypes["6"].items():
	r = rlst[0]
	dll.Handle.seek(r.off)
	rd = r.sz
	txtID = 0
	while rd > 0:
		strLen = read2int(dll.Handle)
		rd -= 2
		s = dll.Handle.read(strLen * 2).decode("UTF-16LE")
		rd -= strLen * 2
		
		if strLen:
			strID[ ((int(rid) - 1) << 4) + txtID ] = s
		
		txtID += 1
	


CmdList = list()

if "SETUPCOMMAND" in pe.ResTypes:
	

	for (did, dat) in pe.ResTypes["SETUPCOMMAND"].items():
		r = dat[0]
		pe.Handle.seek(r.off)
		mdata = pe.Handle.read(r.sz)
		
		cmdid = int.from_bytes(mdata[0:4], byteorder="little")
		cmddat = int.from_bytes(mdata[4:8], byteorder="little")

		if (cmdid == 0x480010): #Copy
			p = GetCMDData( pe, cmddat )
			(d, src) = ParseCStr( p[0x20:] )
			(d, dst) = ParseCStr( d )
		
			#dst = DstPath(dst, strID)
		
			CmdList.append( ("copy", DstPath(src, strID), DstPath(dst, strID)) )
		elif (cmdid == 0x480009): #mkdir
			p = GetCMDData( pe, cmddat )
			(_, dst) = ParseCStr(p[2:])
			CmdList.append( ("mkdir", "", DstPath(dst, strID)) )
		else:
			pass
			#p = GetCMDData( pe, cmddat )
			#print(hex(cmdid), p)

elif ("SETUPBINARY" in pe.ResTypes) and ("SETUPDATA" in pe.ResTypes["SETUPBINARY"]):
	sres = pe.ResTypes["SETUPBINARY"]["SETUPDATA"][0]
	pe.Handle.seek(sres.off)
	setupdata = io.BytesIO( pe.Handle.read(sres.sz) )
	
	cmdcount = read2int(setupdata)
	setupdata.seek(2, 1)
	
	for i in range(cmdcount):
		cmd = read2int(setupdata)
		index = read2int(setupdata)
		unk = read4int(setupdata)
		adsz = read4int(setupdata)
		ad = setupdata.read(adsz)
		
		if (cmd == 8): #mkdir
			(_, dst) = ParseCStr(ad[2:])
			CmdList.append( ("mkdir", "", DstPath(dst, strID)) )
		elif (cmd == 0xf): #copy
			(d, src) = ParseCStr( ad[0x18:] )
			(d, dst) = ParseCStr( d )
		
			#dst = DstPath(dst, strID)
			#print(hex(unk), DstPath(dst, strID))
			if (unk & 0xFF00) == 0 or (unk & 0xFF00) == 0x8000 :  ## Ignore eula shit
				CmdList.append( ("copy", DstPath(src, strID), DstPath(dst, strID)) )		
		else:
			pass

#exit(0)
outpath = sys.argv[2]
while outpath[-1] == "/" or outpath[-1] == "\\":
	outpath = outpath[:-1]

if not os.path.exists(outpath):
	os.makedirs(outpath)

if not os.path.isdir(outpath):
	print(outpath, "not directory")
	exit(1)

outpath += "/"

for (cmd, d1, d2) in CmdList:
	if cmd == "mkdir":
		if not os.path.isdir(outpath + d2):
			os.mkdir(outpath + d2)
		print( "mkdir", outpath + d2)
	elif cmd == "copy":
		if d1 in fileList:
			shutil.copyfile(fileList[d1], outpath + d2)
			print ( "copy", d1, " -> ", outpath + d2)
		else:
			print ( "can't find", d1)
		

#out.close()
