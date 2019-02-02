import subprocess
import tempfile
import logging
import glob
import gdb
import os

import angr
import angrgdb

from .externals import apply_external_simprocs

l = logging.getLogger("deferred_driller.runner")

class PinRunner:
    def __init__(self, binary, argv=None, pin_path=None, pintool_path=None, use_simprocs=True):
        if pin_path is None:
            pin_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "instrumentation", "pin-*", "pin")
            pin_path = glob.glob(pin_path)
            assert len(pin_path) == 1
            pin_path = pin_path[0]
        if pintool_path is None:
            pintool_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "instrumentation", "obj-intel64", "PinTool.so")
        
        self._main_returns = None
        self.binary = binary
        self.cfg = None
        self.objs = None
        
        args = [
            pin_path,
            "-appdebug",
            "-t",
            pintool_path,
            "--",
            binary,
        ]
        if argv is not None:
            args += argv

        os.environ["LD_BIND_NOW"] = "1"
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        '''Application stopped until continued from debugger.
        Start GDB, then issue this command at the (gdb) prompt:
          target remote :56991'''
        self.process.stdout.readline()
        self.process.stdout.readline()
        cmd = self.process.stdout.readline().strip()
        
        gdb.execute(str(cmd, "utf-8"))
        
        self.pid = int(gdb.execute("monitor getpid", to_string=True).strip())
        angrgdb.get_debugger().pid = self.pid
        
        gdb.execute("b *driller_init")
        gdb.execute("continue")
        gdb.execute("monitor enable_fork")
        
        if use_simprocs:
            angrgdb.set_memory_type(angrgdb.SIMPROCS_FROM_CLE)
            apply_external_simprocs()
        else:
            angrgdb.set_memory_type(angrgdb.GET_ALL_DISCARD_CLE)
    
    def brk(self):
        return int(gdb.execute("monitor brk", to_string=True))
    
    def fs(self):
        return int(gdb.execute("monitor fs", to_string=True))
    
    def tracer(self, concrete_input):
        input_path = tempfile.mkstemp(dir="/dev/shm/", prefix="pin-tracer-input-")[1]
        with open(input_path, "wb") as f:
            f.write(concrete_input)
        output_path = tempfile.mkstemp(dir="/dev/shm/", prefix="pin-tracer-log-")[1]      
        
        gdb.execute("monitor input " + input_path)
        gdb.execute("monitor out " + output_path)
        gdb.execute("continue")
        
        trace = []
        crash_addr = None
        with open(output_path, "r") as f:
            while True:
                line = f.readline().strip()
                if len(line) == 0:
                    continue
                if line.startswith("END_OF_TRACE"):
                    if len(line) > len("END_OF_TRACE"):
                        crash_addr = int(line.split()[1])
                    break
                trace.append(int(line))
        
        return trace, crash_addr

    def _driller_init_bounds(self):
        project = angrgdb.load_project()
        if self.cfg is None:
            self.cfg = project.analyses.CFGFast()
        begin = 0xffffffffffffffff
        end = 0
        for bb in project.kb.functions["driller_init"].graph:
            begin = min(begin, bb.addr)
            end = max(end, bb.addr + bb.size)
        return begin, end
    
    def main_return_blocks(self):
        if self._main_returns is None:
            project = angrgdb.load_project()
            if self.cfg is None:
                self.cfg = project.analyses.CFGFast()
            self._main_returns = set()
            for bb in project.kb.functions["main"].blocks: 
                for i in bb.capstone.insns: 
                    if i.mnemonic == "ret":
                        self._main_returns.add(bb.addr)
        return self._main_returns
    
    def get_start_addr(self, trace):
        begin, end = self._driller_init_bounds()
        cnt = 0
        in_init = False
        for addr in trace:
            if addr >= begin and addr < end:
                in_init = True
            elif in_init:
                return addr

