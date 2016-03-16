import os
import os.path
import re
import string
import gc

targetdir="C:\\dump"
windbg="C:\\Program Files (x86)\\Debugging Tools for Windows (x86)\windbg.exe"
symbols="srv*C:\\pdb*http://msdl.microsoft.com/download/symbols"

rptsuffix=".rpt"


class Item:
    def __init__(self):
        self.start=""
        self.end=""

class ThreadInfo:
    def __init__(self):
        self.id=""
        self.tid=0
        self.timems=0

class ThreadPair:
    def __init__(self):
        self.id=""
        self.tid=0
        self.hasstart=False
        self.start=0
        self.hasend=False
        self.end=0
        self.diff=0
################################################################################

def PrintThreadDiffMap(mapThreadDiff):
    for id in mapThreadDiff:
        print(mapThreadDiff[id].id,mapThreadDiff[id].hasend,mapThreadDiff[id].diff)
def PrintThreadDiffList(listThreadDiff):
    for index in range(len(listThreadDiff)):
        print(listThreadDiff[index].id,listThreadDiff[index].hasend,listThreadDiff[index].diff)

def ThreadDiff2SortedList(mapThreadDiff):
    listRst=[]
    mapTmp=mapThreadDiff
    while mapTmp:
        tmpKey = ""
        for i in mapTmp:
            if not tmpKey:
                tmpKey=i
                continue            
            if mapTmp[i].diff > mapTmp[tmpKey].diff:
                tmpKey=i
        listRst.append(mapTmp[tmpKey])
        mapTmp.pop(tmpKey)
    return listRst

def GetFileNameKey(name):
    tmp,ext=os.path.splitext(name);
    filename,ext=os.path.splitext(tmp);
    bstart=0
    if ext==".start":
        bstart=1    
    return filename, bstart;

def IsFilter(name):
    tmp,ext=os.path.splitext(name);
    if ext==rptsuffix:
        return True   
    return False

def AddToMap(key, value, bstart, filelist):
    item=Item()
    if key in filelist:
        item=filelist[key]
        
    if 1==bstart:
        item.start=value
    else:
        item.end=value

    filelist[key]=item
    return

def WriteDiff2File(cmd, listInfo, path):
    f=open(path,"w+")
    f.write("Thread Runaway Diff: \n")
    f.write(">>000:"+cmd+"\n")  
    for i in range(len(listInfo)):
        tmp="\t"+listInfo[i].id+" \t Diff:"+str(listInfo[i].diff)+" \t HasEnd:"+str(listInfo[i].hasend)
        if not listInfo[i].hasend:
            tmp=tmp+" \t RunTimeOnStart:"+str(listInfo[i].start)
        tmp=tmp+"\n"            
        f.write(tmp)
    f.write("\n")  
    f.close
    return

def WriteKB2File(cmd, listInfo, path):
    f=open(path,"a")
    f.write("Thread KB Info: \n")
    f.write(">>000:"+cmd+"\n")  
    for i in range(len(listInfo)):
        tmp="\t"+listInfo[i]+"\n"
        f.write(tmp)
    f.write("\n") 
    f.close
    return
    
def Split2ThreadInfo(item):
    threadinfo=ThreadInfo()
    p=re.compile("^([0-9]+):([\w:]+)\s+([0-9]+)\s+\w+\s+([0-9]+):([0-9]+):([0-9]+)\.([0-9]+)")
    rst=p.findall(item)
    for x in rst:        
        threadinfo.tid=string.atoi(x[0])
        threadinfo.id=x[0]+":"+x[1]
        day=string.atoi(x[2])
        hour=string.atoi(x[3])
        minu=string.atoi(x[4])
        sec=string.atoi(x[5])
        msec=string.atoi(x[6])
        threadinfo.timems= (((day*24+hour)*60+minu)*60+sec)*1000+msec
    return threadinfo

def GetNeedKBTid(listThreadPair):
    total=0
    rst=[]
    for index in range(len(listThreadPair)):
        if(listThreadPair[index].hasend):
            total=total+listThreadPair[index].diff
    tmp=0
    for index in range(len(listThreadPair)):
        if(listThreadPair[index].hasend):
            rst.append(listThreadPair[index].tid)
            tmp=tmp+listThreadPair[index].diff            
            if not tmp*10<total*7:
                break
    return rst

def AnalyzeKB(path):
    if not os.path.exists(path):
        print(path+" not exist")
        return

    begin="ChildEBP RetAddr  Args to Child"
    end="quit:"
    record=False
    rst=[]
    
    f=open(path,"r")
    lines=f.readlines()
    for line in lines:
        tmp=line.strip('\n')
        tmp=tmp.lstrip();
        tmp=tmp.rstrip();
        if 0==cmp(tmp,begin):
            record=True            
        elif 0==cmp(tmp, end):
            record=False
        elif record:
            rst.append(tmp)
    f.close()
    return rst 

def AnalyzeRunaway(path):
    if not os.path.exists(path):
        print(path+" not exist")
        return

    begin="Thread       Time"
    end="quit:"
    record=False
    threads={}
    
    f=open(path,"r")
    lines=f.readlines()
    for line in lines:
        tmp=line.strip('\n')
        tmp=tmp.lstrip();
        tmp=tmp.rstrip();
        if 0==cmp(tmp,begin):
            record=True            
        elif 0==cmp(tmp, end):
            record=False
        elif record:
            info=Split2ThreadInfo(tmp)
            threads[info.id]=info
    return threads    

def CallWindbg(order, path):
    rstpath=path+".dat"
    if os.path.exists(rstpath):
        os.remove(rstpath)
    if not os.path.exists(path):
        print(path+"\t"+"not exist~")
        return ""
    cmd="\""+windbg+"\""+" -z \""+path+"\" -c \""+order+";q\""+" -loga \""+rstpath+"\""+" -y \""+symbols+"\""
    os.system("\""+cmd+"\"")
    print("\t\t"+cmd)
    return rstpath

def DiffThread(mapThreadsStart, mapThreadsEnd):
    mapRst={}
    for id in mapThreadsStart:
        mapRst[id]=ThreadPair()
        mapRst[id].id=mapThreadsStart[id].id;
        mapRst[id].tid=mapThreadsStart[id].tid;
        mapRst[id].start=mapThreadsStart[id].timems;
        mapRst[id].hasstart=True
    for id in mapThreadsEnd:
        item=ThreadPair()
        if id in mapRst:
            item=mapRst[id]
            mapRst.pop(id)
        else:
            item.id=mapThreadsEnd[id].id;
            item.tid=mapThreadsEnd[id].tid;
        item.end=mapThreadsEnd[id].timems;
        item.hasend=True
        item.diff=item.end-item.start
        if 0!=item.diff:
            mapRst[id]=item               
    return mapRst

def PerfAnalyze(dirpath, key, start, end):
    startpath=dirpath+"\\"+start
    endpath=dirpath+"\\"+end
    rptpath=dirpath+"\\"+key+rptsuffix

    startRunawayRstPath=""
    endRunawayRstPath=""
    kbRstPath=""

    if os.path.exists(rptpath):
        os.remove(rptpath)

    cmd="!runaway"
    startRunawayRstPath= CallWindbg(cmd, startpath)
    endRunawayRstPath=CallWindbg(cmd, endpath)
    mapThreadsStart=AnalyzeRunaway(startRunawayRstPath)
    mapThreadsEnd=AnalyzeRunaway(endRunawayRstPath)
    os.remove(startRunawayRstPath)
    os.remove(endRunawayRstPath)

    mapThreadDiff=DiffThread(mapThreadsStart, mapThreadsEnd)
    listThreadDiff=ThreadDiff2SortedList(mapThreadDiff)
    WriteDiff2File(cmd, listThreadDiff, rptpath)
    
    listNeddKBTid=GetNeedKBTid(listThreadDiff)    
    for i in range(len(listNeddKBTid)):
        cmd="~"+str(listNeddKBTid[i])+"s;kb";
        kbRstPath=CallWindbg(cmd, endpath)
        listKBRst=AnalyzeKB(kbRstPath)
        WriteKB2File(cmd, listKBRst, rptpath)
        os.remove(kbRstPath)

    mapThreadsStart.clear()
    mapThreadsEnd.clear()
    mapThreadDiff.clear()
    listThreadDiff=[]
    listNeddKBTid=[]
    listKBRst=[]

################################################################################

def TravelFiles(curDir):
    mapFiles={}
    filecount=0
    for parent, dirnames, filenames in os.walk(curDir):
        if 0 != cmp(parent, curDir):
            continue        
        for filename in filenames:            
            if IsFilter(filename):
                continue
            key, bstart=GetFileNameKey(filename);
            AddToMap(key, filename, bstart, mapFiles)
            filecount=filecount+1
            #print(key,bstart)
    return mapFiles, filecount

        
dirlist=[]
dirlist.append(targetdir)

if not os.path.exists(targetdir):
    print(targetdir, " not exist~")
    
for parent, dirnames, filenames in os.walk(targetdir):
        for dirname in dirnames:
            dirlist.append(parent+"\\"+dirname)

################################################################################

while dirlist:
    dirPath=dirlist[0]
    del dirlist[0]
    
    mapFiles,count=TravelFiles(dirPath)
    print("\n\nCurrent Directory:"+dirPath+"\t Total Files:"+str(count)+"\n\n")
    
    for key,value in mapFiles.items():
        if value.start and value.end:
            print("\ttask:"+key+"\t"+"running...")
            PerfAnalyze(dirPath, key, value.start, value.end)
            print("\tTASK:"+key+"\t"+"OK")
        else:
            print("\tTASK:"+key+"\t"+"NO FILES")
gc.collect()
    

        
