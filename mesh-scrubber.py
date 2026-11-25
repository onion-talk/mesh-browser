import os, shutil, subprocess, time

SRC = os.path.expanduser("~/Mesh-Share")
BASE = os.path.dirname(os.path.abspath(__file__))
CLEAN = os.path.join(BASE, ".clean-share")
TMP = os.path.join(BASE, ".scrub-tmp")
SAFE_TEXT = {".txt", ".md", ".csv", ".json", ".log"}
EPOCH_2000 = (946684800, 946684800)

os.makedirs(SRC, exist_ok=True)
os.makedirs(CLEAN, exist_ok=True)
os.makedirs(TMP, exist_ok=True)

seen = {}

def scrub_one(name):
    src_path = os.path.join(SRC, name)
    dst_path = os.path.join(CLEAN, name)
    tmp_path = os.path.join(TMP, name)
    ext = os.path.splitext(name)[1].lower()

    try:
        shutil.copy2(src_path, tmp_path)
        res = subprocess.run(
            ["mat2", "--inplace", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if res.returncode == 0:
            os.utime(tmp_path, EPOCH_2000)
            os.replace(tmp_path, dst_path)
            print(f"[SCRUBBED] {name}", flush=True)
        elif ext in SAFE_TEXT:
            os.utime(tmp_path, EPOCH_2000)
            os.replace(tmp_path, dst_path)
            print(f"[TEXT OK]  {name}", flush=True)
        else:
            os.remove(tmp_path)
            if os.path.exists(dst_path):
                os.remove(dst_path)
            print(f"[BLOCKED - cannot strip metadata] {name}", flush=True)
    except Exception as e:
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except OSError: pass
        print(f"[ERR] {name}: {e}", flush=True)

while True:
    try:
        current = {}
        for name in os.listdir(SRC):
            if name.startswith("."):
                continue
            p = os.path.join(SRC, name)
            if os.path.isfile(p):
                st = os.stat(p)
                current[name] = (st.st_mtime_ns, st.st_size)

        # Scrub new or modified files
        for name, sig in current.items():
            if seen.get(name) != sig:
                scrub_one(name)
                seen[name] = sig

        # Remove deleted files from the clean vault
        for name in list(seen.keys()):
            if name not in current:
                dst = os.path.join(CLEAN, name)
                if os.path.exists(dst):
                    try: os.remove(dst)
                    except OSError: pass
                del seen[name]
    except Exception:
        pass
    time.sleep(1)
