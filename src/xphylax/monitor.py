import asyncio
import os
from pathlib import Path


async def tail_log_file(path: str):
    file_path = Path(path)
    file_handle = None
    inode = None

    while True:
        try:
            if file_handle is None:
                if not file_path.exists():
                    await asyncio.sleep(1.0)
                    continue
                file_handle = open(file_path, "r", encoding="utf-8", errors="ignore")
                inode = os.fstat(file_handle.fileno()).st_ino
                file_handle.seek(0, os.SEEK_END)

            line = file_handle.readline()
            if line:
                yield line
                continue

            await asyncio.sleep(0.5)
            try:
                stat = file_path.stat()
            except FileNotFoundError:
                file_handle.close()
                file_handle = None
                continue

            if stat.st_ino != inode or stat.st_size < file_handle.tell():
                file_handle.close()
                file_handle = None
                inode = None

        except Exception:
            if file_handle is not None:
                file_handle.close()
            file_handle = None
            inode = None
            await asyncio.sleep(1.0)
