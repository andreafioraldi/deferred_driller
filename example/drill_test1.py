'''
This is a very dirty example.

Commands to run in two different terminals:

~/afl/afl-fuzz -M master -i inputs -o ./output -t 20000 -- ./test1_afl

gdb -q -nh --batch -x drill_test1.py ./test1_driller

Wait AFL to start fuzzing before to run the second command.

'''

import sys, os
cwd = os.path.dirname(os.path.realpath(__file__))
sys.path.append(cwd + "/../")

import json
import base64

from deferred_driller import *

BINARY = "./test1_driller"
STDIN_BOUND = True
EXPLORE_FOUND = False

bmap = open(cwd + "/output/master/fuzz_bitmap", "rb").read()

os.system("mkdir -p %s/output/driller/queue" % cwd)

processed = []
paths = []
index = 0

if os.path.exists(os.path.basename(BINARY) + "-deferred-driller-data.json"):
    jl = json.load(open(os.path.basename(BINARY) + "-deferred-driller-data.json"))
    processed = [base64.b64decode(bytes(x, "utf-8")) for x in jl["processed"]]
    paths = jl["paths"]
    index = jl["index"]

pr = PinRunner(BINARY, use_simprocs=True)

while True:
    for subd in os.listdir(cwd + "/output/"):
        if not os.path.isdir(cwd + "/output/" + subd):
            continue
        for f in os.listdir(cwd + "/output/%s/queue/" % subd):
            if not os.path.exists(cwd + "/output/%s/queue/" % subd + f) or os.path.isdir(cwd + "/output/%s/queue/" % subd + f):
                continue
            target = f[:len("id:......")]
            
            inp = open(cwd + "/output/%s/queue/" % subd + f, "rb").read()
            if inp in processed:
                continue
            
            d = Driller(pr, inp, bmap, explore_found=EXPLORE_FOUND, stdin_bound=STDIN_BOUND)
            
            try:
                for o in d.drill_generator():
                    if o[1] in processed:
                        continue
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
    json.dump({"processed": [str(base64.b64encode(x), "utf-8") for x in processed], "paths": paths, "index": index}, dmp)
    dmp.close()

    resp = input("Go again? [Y,n] ")
    if resp.strip() in ["N","n"]:
        break

