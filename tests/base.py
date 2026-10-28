import os
import shutil
import subprocess
import time
import re

DATA = "./data"
PGR = "./target/debug/pgr"


def sh(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def start_db():
    print("starting db")
    subprocess.run(
        ["pg_ctl", "start", "-D", DATA, "-w", "-l", "pg.log"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )


def stop_db():
    print("stopping db")
    sh("pg_ctl", "stop", "-D", DATA, "-m", "fast", "-w", check=False)


def psql(sql):
    return sh("psql", "-X", "-A", "-t", "-d", "postgres", "-c", sql).stdout.rstrip("\n")


def start_capture() -> str:
    id = int(psql("select pgr.cstart()"))
    path = f"{DATA}/captures/{id}.pr"
    print(f"capture id = {id}, path = {path}")
    return path


def stop_capture():
    print("stopping capture")
    psql("select pgr.cstop()")


def start_timings() -> str:
    id = int(psql("select pgr.timestart()"))
    path = f"{DATA}/timings/{id}.ptm"
    print(f"timings id = {id}, path = {path}")
    return path


def stop_timings():
    print("stopping timings")
    psql("select pgr.timestop()")


def enable_debug_sessions():
    print("enabling debug sessions")
    psql("select pgr.sdebug(true);")


def disable_debug_sessions():
    print("disabling debug sessions")
    psql("select pgr.sdebug(false);")


def remove_debug_sessions():
    print("removing old sessions")
    orig_sessions = os.path.join(DATA, 'sessions', 'd')
    replay_sessions = os.path.join(DATA, 'sessions', 'r')

    if os.path.exists(orig_sessions):
        shutil.rmtree(orig_sessions)
    if os.path.exists(replay_sessions):
        shutil.rmtree(replay_sessions)


def replay(capture_path):
    return subprocess.run([PGR, "replay", capture_path]).returncode


def compare_timings(capture_path, timings_path):
    return subprocess.run(
        [PGR, "compare", "-c", capture_path, "-t", timings_path]
    ).returncode


def get_lsn(capture_path):
    out = sh(PGR, "lsn", capture_path)
    m = re.search(r"LSN:\s*([0-9A-Fa-f]+/[0-9A-Fa-f]+)", out.stdout + out.stderr)
    if not m:
        return None

    return m.group(1)


def wait_promoted():
    print("waiting for promotion")
    while True:
        r = sh(
            "psql",
            "-X",
            "-A",
            "-t",
            "-d",
            "postgres",
            "-c",
            "select pg_is_in_recovery()",
            check=False,
        )
        if r.returncode == 0 and r.stdout.strip() == "f":
            return
        time.sleep(0.5)


def backup():
    stop_db()
    print("doing backup")

    base_dir = os.path.join(DATA, "base")
    global_dir = os.path.join(DATA, "global")

    base_bak = os.path.join(DATA, "base_bak")
    global_bak = os.path.join(DATA, "global_bak")

    if os.path.exists(base_bak):
        shutil.rmtree(base_bak)
    if os.path.exists(global_bak):
        shutil.rmtree(global_bak)

    if os.path.exists(base_dir):
        shutil.copytree(base_dir, base_bak)
    if os.path.exists(global_dir):
        shutil.copytree(global_dir, global_bak)

    start_db()


def recover(lsn: str):
    stop_db()
    print(f"recovering to {lsn}")

    base_dir = os.path.join(DATA, "base")
    global_dir = os.path.join(DATA, "global")

    base_bak = os.path.join(DATA, "base_bak")
    global_bak = os.path.join(DATA, "global_bak")

    if not os.path.exists(base_bak) or not os.path.exists(global_bak):
        raise FileNotFoundError("Backups not found")

    shutil.copytree(base_bak, base_dir, dirs_exist_ok=True)
    shutil.copytree(global_bak, global_dir, dirs_exist_ok=True)

    recovery_signal_path = os.path.join(DATA, "recovery.signal")
    with open(recovery_signal_path, "w", encoding="utf-8") as f:
        pass

    auto_conf_path = os.path.join(DATA, "postgresql.auto.conf")

    settings = [
        f"recovery_target_lsn = '{lsn}'\n",
        "recovery_target_action = 'promote'\n",
        "restore_command = 'cp pg_wal/%f %p'\n",
    ]

    lines = []
    if os.path.exists(auto_conf_path):
        with open(auto_conf_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    lines = [
        line
        for line in lines
        if not line.strip().startswith(
            ("recovery_target_lsn", "recovery_target_action", "restore_command")
        )
    ]
    lines.extend(settings)

    with open(auto_conf_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    start_db()
    wait_promoted()
