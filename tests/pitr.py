import os
import shutil

def backup(folder: str) -> None:
    base_dir = os.path.join(folder, "base")
    global_dir = os.path.join(folder, "global")
    
    base_bak = os.path.join(folder, "base_bak")
    global_bak = os.path.join(folder, "global_bak")

    if os.path.exists(base_bak):
        shutil.rmtree(base_bak)
    if os.path.exists(global_bak):
        shutil.rmtree(global_bak)

    if os.path.exists(base_dir):
        shutil.copytree(base_dir, base_bak)
    if os.path.exists(global_dir):
        shutil.copytree(global_dir, global_bak)

def recover(folder: str, lsn: str) -> None:
    base_dir = os.path.join(folder, "base")
    global_dir = os.path.join(folder, "global")
    
    base_bak = os.path.join(folder, "base_bak")
    global_bak = os.path.join(folder, "global_bak")

    if not os.path.exists(base_bak) or not os.path.exists(global_bak):
        raise FileNotFoundError("Backups not found")
    
    shutil.copytree(base_bak, base_dir, dirs_exist_ok=True)
    shutil.copytree(global_bak, global_dir, dirs_exist_ok=True)

    recovery_signal_path = os.path.join(folder, "recovery.signal")
    with open(recovery_signal_path, "w", encoding="utf-8") as f:
        pass

    auto_conf_path = os.path.join(folder, "postgresql.auto.conf")
    
    settings = [
        f"recovery_target_lsn = '{lsn}'\n",
        "recovery_target_action = 'promote'\n",
        "restore_command = 'cp pg_wal/%f %p'\n"
    ]

    lines = []
    if os.path.exists(auto_conf_path):
        with open(auto_conf_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    lines = [line for line in lines if not line.strip().startswith(("recovery_target_lsn", "recovery_target_action", "restore_command"))]
    lines.extend(settings)

    with open(auto_conf_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
