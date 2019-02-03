#include "pin.H"
#include <iostream>
#include <sstream>
#include <fstream>

#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

using namespace std;

ostream* out = &cerr;

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    return -1;
}


int input_fd;
string trace_filename;

ADDRINT current_brk;

//--------------------------------------------------------------------------------------------

VOID SysCallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    ADDRINT sys_id = PIN_GetSyscallNumber(ctxt, std);
    if(sys_id == SYS_read) {
        ADDRINT fd = PIN_GetSyscallArgument(ctxt, std, 0);
        if(fd == 0) { //change stdin fileno to our input
            PIN_SetSyscallArgument(ctxt, std, 0, input_fd);
        }
    }
}

VOID LogBbl(ADDRINT addr)
{
    *out << addr << endl;
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)LogBbl, IARG_ADDRINT, BBL_Address(bbl), IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    *out << "END_OF_TRACE" << endl;
    if(out != &cerr) {
        delete static_cast<ofstream*>(out);
    }
}

VOID ContextChange(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
{
    if(reason == CONTEXT_CHANGE_REASON_FATALSIGNAL) {
        //TODO crash addr for x86
        *out << "END_OF_TRACE " << PIN_GetContextReg(from, REG_RIP) << endl;
        if(out != &cerr) {
            static_cast<ofstream*>(out)->flush();
        }
    }
}

//--------------------------------------------------------------------------------------------

VOID SysCallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    ADDRINT sys_id = PIN_GetSyscallNumber(ctxt, std);
    if(sys_id == SYS_brk) {
        current_brk = PIN_GetSyscallReturn(ctxt, std);
    }
}


BOOL DebugInterpreter(THREADID tid, CONTEXT *ctxt, const string &cmd, string* result, VOID *);

VOID InChildFork(THREADID threadid, const CONTEXT *ctxt, VOID *v)
{
    cerr << "[in child]\n";
    
    input_fd = open(trace_filename.c_str(), O_RDONLY);
    
    PIN_RemoveDebugInterpreter(DebugInterpreter);
    
    PIN_AddSyscallEntryFunction(SysCallEntry, 0);
    
    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_AddFiniFunction(Fini, 0);
    
    PIN_AddContextChangeFunction(ContextChange, 0);
}

BOOL DebugInterpreter(THREADID tid, CONTEXT *ctxt, const string &cmd, string* result, VOID *)
{
	if(cmd == "getpid") {
	    INT pid = PIN_GetPid();
	    cerr << "[pid = " << pid << "]\n";
		std::ostringstream ss;
	    ss << pid << endl;
	    *result = ss.str();
	    return TRUE;
	}
	else if(cmd == "enable_fork") {
        PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, InChildFork, 0);
        cerr << "[fork hook enabled]\n";
        return TRUE;
	}
	else if(cmd == "fs") {
	    ADDRINT regval;
	    PIN_GetContextRegval(ctxt, REG_SEG_FS_BASE, reinterpret_cast<UINT8*>(&regval));
	    cerr << "[fs base = " << (void*)regval << "]\n";
	    std::ostringstream ss;
	    ss << regval << endl;
	    *result = ss.str();
	    return TRUE;
	}
	else if(cmd == "brk") {
	    cerr << "[brk = " << current_brk << "]\n";
	    std::ostringstream ss;
	    ss << current_brk << endl;
	    *result = ss.str();
	    return TRUE;
	}
	else if(cmd.rfind("input ", 0) == 0) {
		trace_filename = cmd.substr(6);
		cerr << "[input file = " << trace_filename << "]\n";
	    return TRUE;
	}
	else if(cmd.rfind("out ", 0) == 0) {
		string filename = cmd.substr(4);
		cerr << "[out file = " << filename << "]\n";
		out = new ofstream(filename.c_str());
	    return TRUE;
	}
	return FALSE;
}


//env LD_BIND_NOW=1 ../pin-3.7/pin -appdebug -t obj-intel64/PinTool.so -- ../test1

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if(PIN_Init(argc,argv))
        return Usage();
    
    PIN_AddSyscallExitFunction(SysCallExit, 0);
    
    PIN_AddDebugInterpreter(DebugInterpreter, 0);
    
    PIN_StartProgram();
    
    return 0;
}






