from __future__ import annotations

import logging
import os
import shutil
import zipfile
import re

from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from api.schemas.common import TargetInfo, TargetListResponse

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Targets"])

# Resolve the targets/ directory relative to project root
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_TARGETS_DIR = os.path.join(_PROJECT_ROOT, "targets")


@router.get("/targets", response_model=TargetListResponse)
async def list_targets():
    """
    List all available scan targets.

    Scans the `targets/` directory and returns metadata about each target
    including source files, seed availability, and test coverage.
    """
    targets = []

    if not os.path.isdir(_TARGETS_DIR):
        return TargetListResponse(targets=[], count=0)

    for entry in sorted(os.listdir(_TARGETS_DIR)):
        target_path = os.path.join(_TARGETS_DIR, entry)
        if not os.path.isdir(target_path):
            continue

        # Gather metadata
        source_files = [
            f for f in os.listdir(target_path)
            if f.endswith(('.c', '.cpp', '.h'))
        ]

        seeds_dir = os.path.join(target_path, "seeds")
        has_seeds = os.path.isdir(seeds_dir) and bool(os.listdir(seeds_dir))

        tests_dir = os.path.join(target_path, "tests")
        has_tests = os.path.isdir(tests_dir) and bool(os.listdir(tests_dir))

        has_makefile = os.path.isfile(os.path.join(target_path, "Makefile"))

        targets.append(TargetInfo(
            name=entry,
            path=f"targets/{entry}",
            source_files=source_files,
            has_seeds=has_seeds,
            has_tests=has_tests,
            has_makefile=has_makefile,
        ))

    return TargetListResponse(targets=targets, count=len(targets))


@router.post("/targets/upload", response_model=TargetInfo, status_code=201)
async def upload_target(
    file: UploadFile = File(...),
    target_name: str = Form(default=""),
):
    """
    Upload source file (.c/.cpp) or zip archive as a new scan target.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Clean name
    clean_name = re.sub(r'[^a-zA-Z0-9_-]', '_', target_name or os.path.splitext(file.filename)[0])
    if not clean_name:
        clean_name = f"custom_target_{os.urandom(4).hex()}"

    target_dir_name = f"custom_{clean_name}"
    target_dir_path = os.path.join(_TARGETS_DIR, target_dir_name)
    os.makedirs(target_dir_path, exist_ok=True)

    # Read uploaded bytes
    content = await file.read()

    if file.filename.endswith(".zip"):
        zip_temp = os.path.join(target_dir_path, "_upload.zip")
        with open(zip_temp, "wb") as f:
            f.write(content)
        try:
            with zipfile.ZipFile(zip_temp, 'r') as zf:
                zf.extractall(target_dir_path)
        finally:
            if os.path.exists(zip_temp):
                os.remove(zip_temp)
    else:
        # Save individual file
        dest_filename = file.filename if file.filename.endswith(('.c', '.cpp', '.h')) else "vuln.c"
        with open(os.path.join(target_dir_path, dest_filename), "wb") as f:
            f.write(content)

    # Check for source files
    source_files = [f for f in os.listdir(target_dir_path) if f.endswith(('.c', '.cpp', '.h'))]
    if not source_files:
        shutil.rmtree(target_dir_path, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Uploaded package contains no .c or .cpp source files")

    # Generate default Makefile if missing
    makefile_path = os.path.join(target_dir_path, "Makefile")
    if not os.path.exists(makefile_path):
        main_c = next((f for f in source_files if f.endswith(('.c', '.cpp'))), source_files[0])
        with open(makefile_path, "w", encoding="utf-8") as mf:
            mf.write(f"""CC      = gcc
CFLAGS  = -g -O1 -Wall
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer
AFL_CC  = afl-gcc

TARGET  = {target_dir_name}

all: $(TARGET)

$(TARGET): {main_c}
\t$(CC) $(CFLAGS) -o $@ $<

asan: {main_c}
\t$(CC) $(CFLAGS) $(ASAN) -o $(TARGET)_asan $<

afl: {main_c}
\t$(AFL_CC) $(CFLAGS) $(ASAN) -o $(TARGET)_afl $<

clean:
\trm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl

.PHONY: all asan afl clean
""")

    # Generate default seed if missing
    seeds_dir = os.path.join(target_dir_path, "seeds")
    os.makedirs(seeds_dir, exist_ok=True)
    seed_file = os.path.join(seeds_dir, "seed1.txt")
    if not os.path.exists(seed_file):
        with open(seed_file, "w", encoding="utf-8") as sf:
            sf.write("AAAA\n")

    return TargetInfo(
        name=target_dir_name,
        path=f"targets/{target_dir_name}",
        source_files=source_files,
        has_seeds=True,
        has_tests=os.path.isdir(os.path.join(target_dir_path, "tests")),
        has_makefile=True,
    )
