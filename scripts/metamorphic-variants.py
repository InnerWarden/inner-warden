#!/usr/bin/env python3
"""Regenerate crates/agent-guard/corpus/metamorphic/cases.yml.

Takes every must_refuse line of adversarial-323, adversarial-328 and
data-slot-substitutions, rewrites it so bash runs the same command
(quote_split, backslash, variable, line_continuation, absolute_path,
env_prefix, env_redirect, command_prefix, builtin_prefix, extra_whitespace, eval, sh_c,
backticks), and keeps a variant only when it is proven equivalent:

  1. bash -n accepts it (and sh -n accepts the original, for sh_c);
  2. a neutral run gives the same result as the original: bash with PATH
     holding only stubs (each program the lines name prints its arguments
     and stdin to a trace and runs nothing; cat, tee, chmod, xargs and env
     are the real ones), an empty home and an empty working folder. The
     trace, stdout and files left must match.

The comment above each case is the verdict of the guard found as
`innerwarden` on PATH (`innerwarden check --json`, from an empty home).
The file in the repo was written with 1.6.15; another version changes the
comments, not the cases.

Nothing from the corpora runs outside the stubs: the neutral runs have no
real program on PATH but the five above.

Usage:
  python3 scripts/metamorphic-variants.py --corpus-dir crates/agent-guard/corpus \\
      --work /some/empty/dir [--out crates/agent-guard/corpus/metamorphic/cases.yml]

Needs Python 3 with PyYAML, bash and sh at /usr/bin, and timeout, cat and tr
at /usr/bin. --work must be an empty folder you own; it holds the stubs and
the runs and can be removed afterwards.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict

import yaml

ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
ap.add_argument("--corpus-dir", required=True, help="folder holding adversarial-323, adversarial-328 and data-slot-substitutions")
ap.add_argument("--work", required=True, help="an empty folder for the stubs and the neutral runs")
ap.add_argument("--out", help="where to write the corpus (default: <corpus-dir>/metamorphic/cases.yml)")
args = ap.parse_args()
SP = os.path.abspath(args.work)
VERSION = subprocess.run(["innerwarden", "--version"], capture_output=True, text=True).stdout.split()[1]
CD = os.path.abspath(args.corpus_dir)
OUT = args.out or os.path.join(CD, "metamorphic", "cases.yml")
os.makedirs(SP, exist_ok=True)

BT = chr(96)
SRC = [(name, os.path.join(CD, name, "cases.yml"))
       for name in ("adversarial-323", "adversarial-328", "data-slot-substitutions")]

PRIMARY = ["mkfs.ext4","systemctl","launchctl","busctl","pkill","kill","curl","wget","crontab"]
KEYWORDS = {"if","then","else","fi","for","do","done","while","time","true","command","eval","in","function","EOF"}
BUILTINS = {"kill","eval","echo","printf","cd","true"}
ABS = {"git":"/usr/bin/git","curl":"/usr/bin/curl","wget":"/usr/bin/wget","mkfs.ext4":"/usr/sbin/mkfs.ext4",
       "systemctl":"/usr/bin/systemctl","pkill":"/usr/bin/pkill","pgrep":"/usr/bin/pgrep","kill":"/usr/bin/kill",
       "busctl":"/usr/bin/busctl","perl":"/usr/bin/perl","python3":"/usr/bin/python3","bash":"/usr/bin/bash",
       "sh":"/usr/bin/sh","make":"/usr/bin/make","awk":"/usr/bin/awk","sudo":"/usr/bin/sudo","cat":"/usr/bin/cat"}

def code_mask(line):
    mask = [True]*len(line); i=0; sq=False; dq=False; pending=[]
    while i < len(line):
        c = line[i]
        if sq:
            mask[i]=False
            if c=="'": sq=False
            i+=1; continue
        if c=="\\" and i+1 < len(line): i+=2; continue
        if c=='"': dq = not dq
        elif c=="'" and not dq: sq=True; mask[i]=False
        elif line[i:i+2]=="<<" and line[i:i+3]!="<<<":
            m = re.match(r"<<-?\s*(['\"]?)(\w+)\1", line[i:])
            if m: pending.append(m.group(2)); i+=m.end(); continue
        elif c=="\n" and pending:
            j=i+1
            for term in pending:
                while j < len(line):
                    e = line.find("\n", j); e = len(line) if e<0 else e
                    body = line[j:e]
                    for k in range(j, min(e+1,len(line))): mask[k]=False
                    j = e+1
                    if body.strip()==term: break
            pending=[]; i=j; continue
        i+=1
    return mask

CMDPOS = re.compile(r"(?:^|(?<=[\n;&|({" + BT + r"])|(?<=\$\()|(?<=<\()|(?<=>\())[ \t]*([A-Za-z_][A-Za-z0-9_.+-]*)(?=[ \t\n;|&)" + BT + r"]|$)")
def command_words(line):
    mask = code_mask(line); out=[]
    fns = set(re.findall(r"(\w+)\(\)\s*\{", line))
    for m in CMDPOS.finditer(line):
        s = m.start(1); w = m.group(1)
        if not mask[s] or w in KEYWORDS or w in fns: continue
        out.append((s, w))
    return out

def target(line):
    ws = command_words(line)
    for p in PRIMARY:
        for s,w in ws:
            if w==p: return s,w
    return ws[0] if ws else None

def sq(s): return "'" + s.replace("'", "'\\''") + "'"

def backticks(line):
    mask = code_mask(line); out=line; spans=[]
    for m in re.finditer(r"\$\(", line):
        if not mask[m.start()]: continue
        depth=0; j=m.start()+1
        while j < len(line):
            if line[j]=="(": depth+=1
            elif line[j]==")":
                depth-=1
                if depth==0: break
            j+=1
        if j>=len(line): continue
        inner = line[m.start()+2:j]
        if "$(" in inner or BT in inner or "\\" in inner or "(" in inner or not inner.strip(): continue
        spans.append((m.start(), j, inner))
    for a,b,inner in sorted(spans, reverse=True):
        out = out[:a] + BT + inner + BT + out[b+1:]
    return out if spans else None

def variants(line):
    t = target(line); v={}
    if t:
        s,w = t; e = s+len(w); rest=line[e:]
        v["quote_split"] = line[:s] + w[0]+"''"+w[1:] + rest
        v["backslash"] = line[:s] + w[0]+"\\"+w[1:] + rest
        v["variable"] = "IWV="+w+"; " + line[:s] + "$IWV" + rest
        if rest[:1]==" ": v["line_continuation"] = line[:e] + " \\\n  " + rest[1:]
        if w in ABS: v["absolute_path"] = line[:s] + ABS[w] + rest
        v["env_prefix"] = line[:s] + "env " + w + rest
        v["env_redirect"] = line[:s] + "env 2>/dev/null " + w + rest
        v["command_prefix"] = line[:s] + "command " + w + rest
        if w in BUILTINS: v["builtin_prefix"] = line[:s] + "builtin " + w + rest
        if rest[:1]==" ": v["extra_whitespace"] = line[:s] + " \t" + w + " \t " + rest[1:]
    v["eval"] = "eval " + sq(line)
    v["sh_c"] = "sh -c " + sq(line)
    b = backticks(line)
    if b: v["backticks"] = b
    return t, v

STUBS = ("gh git curl wget mkfs.ext4 systemctl launchctl pkill pgrep kill busctl perl php lua ruby python3 node bash sh "
         "at crontab tcsh busybox make awk parallel npx npm pytest cargo brew sudo gunzip jest").split()
REAL = ["cat","tee","chmod","xargs","env"]
def mkstubs(d):
    os.makedirs(d, exist_ok=True)
    for n in STUBS:
        p=os.path.join(d,n)
        with open(p,"w") as f:
            f.write('#!/usr/bin/bash\nn=$(/usr/bin/basename "$0"); e="[$n]"; for a in "$@"; do e="$e <$a>"; done\n'
                    'if [ ! -t 0 ]; then e="$e stdin=$(/usr/bin/timeout 1 /usr/bin/cat | /usr/bin/tr "\\n" "~")"; fi\n'
                    'printf "%s\\n" "$e" >> "$IWTRACE"; printf "out-of-%s\\n" "$n"\n')
        os.chmod(p,0o755)
    for n in REAL:
        q=os.path.join(d,n)
        if not os.path.lexists(q): os.symlink("/usr/bin/"+n, q)
STUBDIR = SP+"/stubs"; mkstubs(STUBDIR)

def neutral(line, tech=None):
    run = line
    if tech=="absolute_path":
        for w,p in ABS.items(): run = run.replace(p, STUBDIR+"/"+w)
    if tech=="sh_c": run = "/usr/bin/sh" + run[2:]
    base = tempfile.mkdtemp(dir=SP, prefix="run-")
    home=base+"/home"; work=base+"/work"; os.makedirs(home); os.makedirs(work+"/.git/hooks")
    tr = base+"/trace"; open(tr,"w").close()
    try:
        p = subprocess.run(["/usr/bin/bash","-c",run], cwd=work, env={"PATH":STUBDIR,"HOME":home,"IWTRACE":tr},
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        out = p.stdout
    except subprocess.TimeoutExpired:
        out="TIMEOUT"
    trace = sorted(open(tr).read().splitlines())
    files = {}
    for root in (home, work):
        for dp,_,fs in os.walk(root):
            for f in fs:
                fp=os.path.join(dp,f)
                try: files[os.path.relpath(fp,base)] = open(fp,errors="replace").read()
                except Exception: files[os.path.relpath(fp,base)]="?"
    shutil.rmtree(base)
    return {"out":out,"trace":trace,"files":files}

def verdict(line, home):
    p = subprocess.run(["innerwarden","check","--json",line],capture_output=True,text=True,env={**os.environ,"HOME":home},cwd=home)
    try:
        j=json.loads(p.stdout); return j["recommendation"], j.get("explanation","")
    except Exception: return "error", p.stdout[:200]+p.stderr[:200]

CHKHOME = tempfile.mkdtemp(dir=SP, prefix="home-")
res=[]
for corpus, path in SRC:
    data = yaml.safe_load(open(path))
    for c in data["cases"]:
        if not c.get("must_refuse"): continue
        line=c["input"]
        t, vs = variants(line)
        base_n = neutral(line)
        ov = verdict(line, CHKHOME)
        for tech, vl in vs.items():
            if vl==line: continue
            ok = subprocess.run(["/usr/bin/bash","-n","-c",vl],capture_output=True).returncode==0
            if tech=="sh_c":
                ok = ok and subprocess.run(["/usr/bin/sh","-n","-c",line],capture_output=True).returncode==0
            n = neutral(vl, tech) if ok else None
            same = bool(ok and n["trace"]==base_n["trace"] and n["files"]==base_n["files"] and n["out"]==base_n["out"])
            res.append({"corpus":corpus,"orig":c["id"],"category":c["category"],"tech":tech,"target":t[1] if t else None,
                        "orig_input":line,"input":vl,"syntax":ok,"same":same,"orig_verdict":ov,
                        "verdict": verdict(vl, CHKHOME) if ok else None,
                        "diff": None if same or not ok else {"base":base_n,"var":n}})
R = res

keep = [r for r in R if r["syntax"] and r["same"]]
RANK = {"allow":0,"review":1,"deny":2}
SHORT = {"quote_split":"quote","backslash":"esc","variable":"var","line_continuation":"cont","eval":"eval","sh_c":"shc",
         "absolute_path":"abs","env_prefix":"env","env_redirect":"envr","command_prefix":"cmd","builtin_prefix":"builtin","extra_whitespace":"ws","backticks":"bt"}
def clean(s):
    s = s.replace(SP, "<dir>")
    s = re.sub(r"/home/[^ /]+", "~", s)
    return s[:110]
drops = defaultdict(Counter)
L = []
L.append("""# Metamorphic variants of the must_refuse lines of adversarial-323,
# adversarial-328 and data-slot-substitutions: the same command written so
# bash runs it the same way, so the verdict should not move. Each case names
# the line it rewrites with variant_of (the original's id in its corpus).
#
# Techniques (category variant_<technique>), applied to one command word of
# the line: the first of mkfs.ext4, systemctl, launchctl, busctl, pkill,
# kill, curl, wget, crontab in a command position, else the first command
# word outside quotes and here-document bodies:
#   quote_split        c''url
#   backslash          c\\url
#   variable           IWV=curl; ... $IWV
#   line_continuation  curl \\<newline> -s ...
#   absolute_path      /usr/bin/curl (only where the program lives there)
#   env_prefix         env curl
#   env_redirect       env 2>/dev/null curl
#   command_prefix     command curl
#   builtin_prefix     builtin kill (only for a shell builtin)
#   extra_whitespace   a space and a tab around the word
#   eval               eval '<line>'
#   sh_c               sh -c '<line>'
#   backticks          each simple $(...) written with backticks
#
# How each variant was kept: bash -n accepts it (sh -n too for sh_c), and a
# neutral run gives the same result as the original. The neutral run is bash
# with PATH holding only stubs (every program the lines name prints its
# arguments and stdin to a trace and runs nothing; cat, tee, chmod, xargs and
# env are the real ones), an empty home and an empty working folder; the
# trace, stdout and files left must match. absolute_path and sh_c runs point
# the path at the stub and sh -c at the real sh. Variants that did not match
# were left out: env in front of a shell builtin (kill, echo, printf) runs the
# external program, and sh -c of a line in bash-only syntax fails.
#
# The comment above each case is the verdict of the released guard
# (innerwarden check, 1.6.15, 2026-11-20, from an empty home), then the
# original's when it differs. Downloads come from e.example; the format
# target is /dev/sda1. Nothing in this file is executed.
#""")
body = ["cases:"]
for r in keep:
    v, why = r["verdict"]; ov = r["orig_verdict"][0]
    if RANK[v] < RANK[ov]: drops[r["tech"]][ov+" to "+v] += 1
    cmt = "  # %s: %s (%s)" % (VERSION, v, clean(why))
    if v != ov: cmt += "; original: " + ov
    body.append(cmt)
    body.append("  - id: %s-m-%s" % (r["orig"], SHORT[r["tech"]]))
    body.append("    category: variant_%s" % r["tech"])
    body.append("    label: malicious")
    body.append("    input: " + json.dumps(r["input"], ensure_ascii=False))
    body.append("    must_refuse: true")
    body.append("    variant_of: %s" % r["orig"])
# summary table in header
tech_n = Counter(r["tech"] for r in keep)
L.append("# Kept variants and how many fall from the original's verdict on %s:" % VERSION)
L.append("#   %-18s %5s %15s %15s %16s" % ("technique","kept","deny to review","deny to allow","review to allow"))
for t in SHORT:
    if t in tech_n:
        d = drops[t]
        L.append("#   %-18s %5d %15d %15d %16d" % (t, tech_n[t], d["deny to review"], d["deny to allow"], d["review to allow"]))
out = "\n".join(L) + "\n" + "\n".join(body) + "\n"
os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write(out)
y = yaml.safe_load(out)
ids = [c["id"] for c in y["cases"]]
assert len(ids)==len(set(ids)), "dup ids"
for c,r in zip(y["cases"], keep): assert c["input"]==r["input"]
print(len(ids), "cases written to", OUT)
print("\n".join(L[-14:]))
