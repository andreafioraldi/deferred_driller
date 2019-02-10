'''
This is a very dirty example.

Commands to run in two different terminals:

~/afl/afl-fuzz -M master -i inputs -o ./output -t 20000 -- ./test1_afl

gdb -q -nh --batch -x drill.py ./test1_driller

Wait AFL to start fuzzing before to run the second command.

'''

import sys, os
cwd = os.path.dirname(os.path.realpath(__file__))
sys.path.append(cwd + "/../")

import json
import time
import base64
import tempfile
import hashlib
import logging

from deferred_driller import *

l = logging.getLogger("drill_this_shit")
l.setLevel(logging.INFO)

BINARY = "./test1_driller"
STDIN_BOUND = True
EXPLORE_FOUND = False
MINIMIZE = True

os.system("mkdir -p %s/output/driller/queue" % cwd)

if os.path.exists(os.path.basename(BINARY) + "-deferred-driller-data.json"):
    restore = json.load(open(os.path.basename(BINARY) + "-deferred-driller-data.json"))
    processed = restore["processed"]
    transitions = restore["transitions"]
    index = restore["index"]
else:
    processed = []
    transitions = []
    index = 0

runner = PinRunner(BINARY, use_simprocs=True)

while True:
    for subd in os.listdir(cwd + "/output/"):
        if not os.path.isdir(cwd + "/output/" + subd):
            continue
        
        stats = open(cwd + "/output/%s/fuzzer_stats"%subd)
        pfavs = None
        for line in stats:
            if line.startswith("pending_favs"):
                pfavs = line.split(":")[1].strip()
                break
        if pfavs != "0":
            l.debug("%s pending_favs != 0" % subd)
            break
        
        for f in os.listdir(cwd + "/output/%s/queue/" % subd):
            if not os.path.exists(cwd + "/output/%s/queue/" % subd + f) or os.path.isdir(cwd + "/output/%s/queue/" % subd + f):
                continue
            target = f[:len("id:......")]
            l.debug("targetting " + cwd + "/output/%s/queue/" % subd + f)

            if MINIMIZE:
                minimized = tempfile.mkstemp(dir="/tmp/", prefix="driller-minimized-")[1]
                r = os.system("~/afl/afl-tmin -t 20000 -i '%s' -o %s -- %s" % (cwd + "/output/%s/queue/" % subd + f, minimized, BINARY.replace("driller", "afl")))
                l.debug("afl-tmin ret val:", r)
                if r == 0:
                    input_data = open(minimized, "rb").read()
                else:
                    input_data = open(cwd + "/output/%s/queue/" % subd + f, "rb").read()
                os.unlink(minimized)
            else:
                input_data = open(cwd + "/output/%s/queue/" % subd + f, "rb").read()
            
            inp_hash = hashlib.md5(input_data).hexdigest()
            if inp_hash in processed:
                l.debug(f + " already processed (md5 = %s)" % inp_hash)
                continue
            processed.append(inp_hash)
            
            ### hack for strncmp not satisfiable diverted state, see https://github.com/shellphish/driller/issues/70
            if len(input_data) < 100:
                input_data = input_data.ljust(100, b"\x00") # this is shit cause this can alter the behaviour of a generic program and slowdown the exploration
            
            bmap = open(cwd + "/output/master/fuzz_bitmap", "rb").read()
            d = Driller(runner, input_data, bmap, explore_found=EXPLORE_FOUND, stdin_bound=STDIN_BOUND)
            
            try:
                for o in d.drill_generator():
                    if o[0] in transitions:
                        continue
                    index += 1
                    out = open(cwd + "/output/driller/queue/id:%06d,src:%s" % (index, target), "wb")
                    out.write(o[1])
                    out.close()
                    transitions.append(o[0])
            except Exception as ee:
                l.warning("!!! ERROR !!!")
                import traceback
                traceback.print_exc()
    
            l.info("saving stuffs...")
            with open(os.path.basename(BINARY) + "-deferred-driller-data.json", "w") as dmp:
                json.dump({"processed": processed, "transitions": transitions, "index": index}, dmp)


