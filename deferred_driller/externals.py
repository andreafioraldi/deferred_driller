import os
import logging
from collections import defaultdict

import angr
import angrgdb

l = logging.getLogger("deferred_driller.externals")
l.setLevel(logging.INFO)

def get_objects(p):
    vmmap = angrgdb.get_debugger()._get_vmmap()
    objs = defaultdict(lambda: [0xffffffffffffffff, 0])
    paths = []
    for dep in p.loader.main_object.deps:
        paths += p.loader._possible_paths(dep)
    
    for start, end, mapperm, mapname in vmmap:
        if not os.path.exists(mapname):
            continue
        if mapname == p.loader.main_object.binary:
            continue
        if mapname not in paths: #skip pinbin PinTool.so etc...
            continue
        objs[mapname][0] = min(objs[mapname][0], start)
        objs[mapname][1] = max(objs[mapname][1], end)
    return objs


def get_got(p):
    s = list(filter(lambda x: x.name == ".got.plt", p.loader.main_object.sections))[0]
    return (s.vaddr, s.vaddr + s.memsize)

def get_plt(p):
    s = list(filter(lambda x: x.name == ".plt", p.loader.main_object.sections))[0]
    return (s.vaddr, s.vaddr + s.memsize)

def process_got(proj):
    debugger = angrgdb.get_debugger()
    target_proj = angrgdb.load_project()
    
    got_start, got_end = get_got(proj)
    plt_start, plt_end = get_plt(proj)
    
    entry_len = proj.arch.bits // 8
    get_mem = debugger.get_dword if entry_len == 4 else debugger.get_qword

    got_start += 3 * entry_len  # skip first 3 entries
    empty_state = proj.factory.blank_state()

    for a in range(got_start, got_end, entry_len):
        state_val = empty_state.solver.eval(getattr(empty_state.mem[a], "uint%d_t" % proj.arch.bits).resolved)
        
        if state_val in proj._sim_procedures:
            dbg_val = get_mem(a)
            name = proj._sim_procedures[state_val].display_name
            
            if proj._sim_procedures[state_val].is_stub:
                l.debug("Skipping re-hooking of %s cause is a stub" % name)
            elif not target_proj.is_hooked(dbg_val):
                l.info("Re-hooking %s (got: 0x%x) to 0x%x" % (name, a, dbg_val))
                target_proj.hook_symbol(dbg_val, proj._sim_procedures[state_val])


def apply_external_simprocs():
    objs = get_objects(angrgdb.load_project())
    for o in objs:
        l.info("Applying simprocs to " + o)
        try:
            p = angr.Project(o, main_opts={ 'base_addr': objs[o][0] , 'force_rebase': True}, load_options={ "auto_load_libs": False })
            process_got(p)
        except Exception as ee:
            l.warning("Failed to apply simprocs to " + o + ": " + str(ee))



