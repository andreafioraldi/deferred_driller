import os
import time
import signal
import hashlib
import resource
import pickle
import logging
import binascii

import angr
import angrgdb

import progressbar

from .tracer import Tracer
from .exploration import DrillerCore
from . import config

l = logging.getLogger("deferred_driller.core")
l.setLevel(logging.INFO)

class Driller(object):
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """

    def __init__(self, runner, input_str, fuzz_bitmap=None, tag=None, redis=None, hooks=None, exclude_simprocs=[], stdin_bound=True, sync_brk=True, sync_fs=True, explore_found=True, zero_fill=False):
        """
        :param runner           : The PinRunner instance.
        :param input_str        : Input string to feed to the binary.
        :param fuzz_bitmap      : AFL's bitmap of state transitions (defaults to empty).
        :param redis            : redis.Redis instance for coordinating multiple Driller instances.
        :param hooks            : Dictionary of addresses to simprocedures.
        :param use_simprocs     : Use simprocedures
        :param exclude_simprocs : List of names of imports to exclude from simprocedures
        :param stdin_bound      : Bound read stdin
        :param sync_brk         : Synchronize brk value
        :param sync_fs          : Synchronize fs base value
        :param explore_found    : Explore the deferred state to some extent 
        """

        self.runner           = runner
        # Redis channel identifier.
        self.identifier       = os.path.basename(runner.binary)
        self.input            = input_str
        self.fuzz_bitmap      = fuzz_bitmap
        self.tag              = tag
        self.redis            = redis
        self.exclude_simprocs = exclude_simprocs
        self.stdin_bound      = stdin_bound
        self.sync_brk         = sync_brk
        self.sync_fs          = sync_fs
        self.explore_found    = explore_found
        self.zero_fill        = zero_fill
        self.base = os.path.join(os.path.dirname(__file__), "..")

        # The simprocedures.
        self._hooks = {} if hooks is None else hooks

        # The driller core, which is now an exploration technique in angr.
        self._core = None

        # Start time, set by drill method.
        self.start_time = time.time()

        # Set of all the generated inputs.
        self._generated = set()

        # Set the memory limit specified in the config.
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

        l.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self.start_time))

### DRILLING

    def drill(self):
        """
        Perform the drilling, finding more code coverage based off our existing input base.
        """

        # Don't re-trace the same input.
        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
            return -1

        # Write out debug info if desired.
        if l.level == logging.DEBUG and config.DEBUG_DIR:
            self._write_debug_info()
        elif l.level == logging.DEBUG and not config.DEBUG_DIR:
            l.warning("Debug directory is not set. Will not log fuzzing bitmap.")

        # Update traced.
        if self.redis:
            self.redis.sadd(self.identifier + '-traced', self.input)

        list(self._drill_input())

        if self.redis:
            return len(self._generated)
        else:
            return self._generated

    def drill_generator(self):
        """
        A generator interface to the actual drilling.
        """

        # Set up alarm for timeouts.
        if config.DRILL_TIMEOUT is not None:
            signal.alarm(config.DRILL_TIMEOUT)

        for i in self._drill_input():
            yield i

    def _drill_input(self):
        """
        Symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        state transitions.
        """
        
        p = angrgdb.load_project()
        
        trace, crash_addr = self.runner.tracer(self.input)
        start_addr = self.runner.get_start_addr(trace)
        
        for bb in self.runner.main_return_blocks():
            try:
                idx = trace.index(bb)
            except ValueError:
                continue
            trace = trace[:idx +1]
        
        for addr, proc in self._hooks.items():
            p.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)
        
        s = angrgdb.StateShot(sync_brk=False, concrete_imports=self.exclude_simprocs, stdin=angr.SimFileStream)
        
        if self.zero_fill:
            s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        
        if self.sync_brk: # don't use angrdbg brk but ask for it to the runner
            s.posix.set_brk(s.solver.BVV(self.runner.brk(), p.arch.bits))
        if self.sync_fs:
            s.regs.fs = self.runner.fs()
        s.regs.rax = 0xabadcafe #flag for exit driller_init
        
        s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, self.stdin_bound)

        simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=True)
        
        start_addr = self.runner.get_start_addr(trace)
        
        t = Tracer(start_addr, trace=trace, crash_addr=crash_addr)
        self._core = DrillerCore(trace=trace, fuzz_bitmap=self.fuzz_bitmap)

        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self._core)

        self._set_concretizations(simgr.one_active)

        l.info("Drilling into %r.", self.input)
        l.debug("Input is %r.", self.input)
        
        start_addr_idx = trace.index(start_addr)
        with progressbar.ProgressBar(max_value=(len(trace) - start_addr_idx)) as bar:
            while simgr.active and simgr.one_active.globals['trace_idx'] < len(trace) - 1:
                simgr.step()
                #print("RIP", simgr.one_active.regs.rip)
                #print("TRACE", simgr.one_active.globals['trace_idx'], hex(trace[simgr.one_active.globals['trace_idx']]))
                bar.update(simgr.one_active.globals['trace_idx'] - start_addr_idx)
                l.debug("stepped to " + str(simgr.one_active.regs.rip))
                
                if len(simgr.unconstrained) > 0:
                    while len(simgr.unconstrained) > 0:
                        state = simgr.unconstrained.pop(0)
                        l.debug("Found a unconstrained state, exploring to some extent.")
                        w = self._writeout(state.history.bbl_addrs[-1], state)
                        if w is not None:
                            yield w
                
                # Check here to see if a crash has been found.
                if self.redis and self.redis.sismember(self.identifier + '-finished', True):
                    return

                if 'diverted' not in simgr.stashes:
                    continue

                while simgr.diverted:
                    state = simgr.diverted.pop(0)
                    l.debug("Found a diverted state, exploring to some extent.")
                    w = self._writeout(state.history.bbl_addrs[-1], state)
                    if w is not None:
                        yield w
                    if self.explore_found:
                        for i in self._symbolic_explorer_stub(state):
                            yield i

### EXPLORER

    def _symbolic_explorer_stub(self, state):
        # Create a new simulation manager and step it forward up to 1024
        # accumulated active states or steps.
        steps = 0
        accumulated = 1

        p = state.project
        state = state.copy()
        try:
            state.options.remove(angr.options.LAZY_SOLVES)
        except KeyError:
            pass
        simgr = p.factory.simulation_manager(state, hierarchy=False)

        l.info("[%s] started symbolic exploration at %s.", self.identifier, time.ctime())

        while len(simgr.active) and accumulated < 1024:
            simgr.step()
            steps += 1

            # Dump all inputs.
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))

        l.info("[%s] stopped symbolic exploration at %s.", self.identifier, time.ctime())

        for dumpable in simgr.deadended:
            try:
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
                    if w is not None:
                        yield w

            # If the state we're trying to dump wasn't actually satisfiable.
            except IndexError:
                pass

### UTILS

    @staticmethod
    def _set_concretizations(state):
        if state.project.loader.main_object.os == 'cgc':
            flag_vars = set()
            for b in state.cgc.flag_bytes:
                flag_vars.update(b.variables)

            state.unicorn.always_concretize.update(flag_vars)

        # Let's put conservative thresholds for now.
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    def _in_catalogue(self, length, prev_addr, next_addr):
        """
        Check if a generated input has already been generated earlier during the run or by another
        thread.

        :param length   : Length of the input.
        :param prev_addr: The source address in the state transition.
        :param next_addr: The destination address in the state transition.

        :return: boolean describing whether or not the input generated is redundant.
        """

        key = '%x,%x,%x\n' % (length, prev_addr, next_addr)

        if self.redis:
            return self.redis.sismember(self.identifier + '-catalogue', key)

        # No redis means no coordination, so no catalogue.
        else:
            return False

    def _add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x,%x,%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key)
        # No redis = no catalogue.

    def _writeout(self, prev_addr, state):
        generated = state.posix.stdin.load(0, state.posix.stdin.pos)
        generated = state.solver.eval(generated, cast_to=bytes)

        key = (len(generated), prev_addr, state.addr)

        # Checks here to see if the generation is worth writing to disk.
        # If we generate too many inputs which are not really different we'll seriously slow down AFL.
        if self._in_catalogue(*key):
            self._core.encounters.remove((prev_addr, state.addr))
            return None

        else:
            self._add_to_catalogue(*key)

        l.info("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

        self._generated.add((key, generated))

        if self.redis:
            # Publish it out in real-time so that inputs get there immediately.
            channel = self.identifier + '-generated'

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag}))

        else:
            l.info("Generated: %s", binascii.hexlify(generated))

        return (key, generated)

    def _write_debug_info(self):
        m = hashlib.md5()
        m.update(self.input)
        f_name = os.path.join(config.DEBUG_DIR, self.identifier + '_' + m.hexdigest() + '.py')

        with open(f_name, 'w+') as f:
            l.debug("Debug log written to %s.", f_name)
            f.write("binary = %r\n" % self.binary
                    + "started = '%s'\n" % time.ctime(self.start_time)
                    + "input = %r\n" % self.input
                    + "fuzz_bitmap = %r" % self.fuzz_bitmap)
