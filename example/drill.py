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

from deferred_driller import *

BINARY = "./test1_driller"
STDIN_BOUND = True
EXPLORE_FOUND = True
MINIMIZE = False

bmap = open(cwd + "/output/master/fuzz_bitmap", "rb").read()

os.system("mkdir -p %s/output/driller/queue" % cwd)

processed = []
paths = []
index = 0

if os.path.exists(os.path.basename(BINARY) + "-deferred-driller-data.json"):
    jl = json.load(open(os.path.basename(BINARY) + "-deferred-driller-data.json"))
    processed = jl["processed"]
    paths = jl["paths"]
    index = jl["index"]

pr = PinRunner(BINARY, use_simprocs=True)

while True:
    #print("waiting while pending_favs != 0")
    while True:
        stats = open(cwd + "/output/master/fuzzer_stats")
        pfavs = None
        for l in stats:
            if l.startswith("pending_favs"):
                pfavs = l.split(":")[1].strip()
                break
        if pfavs == "0":
            #print("pending_favs = 0")
            break
        time.sleep(2)
    
    for subd in os.listdir(cwd + "/output/"):
        if not os.path.isdir(cwd + "/output/" + subd):
            continue
        for f in os.listdir(cwd + "/output/%s/queue/" % subd):
            if not os.path.exists(cwd + "/output/%s/queue/" % subd + f) or os.path.isdir(cwd + "/output/%s/queue/" % subd + f):
                continue
            target = f[:len("id:......")]
            
            if MINIMIZE:
                minimized = tempfile.mkstemp(dir="/tmp/", prefix="driller-minimized-")[1]
                r = os.system("~/afl/afl-tmin -t 20000 -i '%s' -o %s -- %s" % (cwd + "/output/%s/queue/" % subd + f, minimized, BINARY.replace("driller", "afl")))
                print("afl-tmin ret val:", r)
                if r == 0:
                    inp = open(minimized, "rb").read()
                else:
                    inp = open(cwd + "/output/%s/queue/" % subd + f, "rb").read()
                os.unlink(minimized)
            else:
                inp = open(cwd + "/output/%s/queue/" % subd + f, "rb").read()
            inp_hash = hashlib.md5(inp).hexdigest()
            if inp_hash in processed:
                continue
            processed.append(inp_hash)
            
            ### hack for strncmp not satisfiable diverted state, see https://github.com/shellphish/driller/issues/70
            if len(inp) < 100:
                inp = inp.ljust(100, b"\x00")
            
            bmap = open(cwd + "/output/master/fuzz_bitmap", "rb").read()
            d = Driller(pr, inp, bmap, explore_found=EXPLORE_FOUND, stdin_bound=STDIN_BOUND)
            
            try:
                for o in d.drill_generator():
                    if o[0] in paths:
                        continue

                    index += 1
                    out = open(cwd + "/output/driller/queue/id:%06d,src:%s" % (index, target), "wb")
                    out.write(o[1])
                    out.close()
                    paths.append(o[0])
            except Exception as ee:
                print("!!! ERROR !!!")
                print(ee)
                import traceback
                traceback.print_exc()
                print()
    
            print("Saving...")
            dmp = open(os.path.basename(BINARY) + "-deferred-driller-data.json", "w")
            json.dump({"processed": processed, "paths": paths, "index": index}, dmp)
            dmp.close()



