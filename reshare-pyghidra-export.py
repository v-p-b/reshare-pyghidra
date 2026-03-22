# ReShare exporter
# @author buherator
# @category _NEW_
# @keybinding
# @menupath
# @toolbar
# @runtime pyghidra

import json
import logging
import os

from ghidra.program.model.data import DataType

try:
    from ghidra.ghidra_builtins import currentProgram, writer
except ImportError:
    pass
from javax.swing import JFileChooser
from reshare_pyghidra import ReshGhidraExporter

# -----------------------------------------------------------------------------

LOG_FILE = None
LOG_LEVEL = logging.DEBUG
EXPORT_PATH = os.environ.get("EXPORT_PATH","/tmp/reshare.json")
SOURCE_ARCHIVE_PREFIX = ""

# -----------------------------------------------------------------------------

logger = logging.getLogger()

log_fmt = logging.Formatter("[%(levelname)s](%(asctime)s) %(message)s")
handlers = [
    logging.StreamHandler(writer),
]

if LOG_FILE is not None:
    handlers.append(logging.FileHandler(LOG_FILE))

logger.handlers.clear()
logger.setLevel(LOG_LEVEL)
for h in handlers:
    h.setLevel(LOG_LEVEL)
    h.setFormatter(log_fmt)
    logger.addHandler(h)

logger.info(f"Exporting to: {EXPORT_PATH}")

def type_filter_cb(dt: DataType) -> bool:
    archive_name = dt.getSourceArchive().getName()
    if not archive_name.startswith(SOURCE_ARCHIVE_PREFIX):
        return False
    return True

exporter=ReshGhidraExporter(currentProgram)
exporter.add_data_type_filter(type_filter_cb)
export=exporter.export()

with open(EXPORT_PATH, "w") as out:
    out.write(json.dumps(export.to_json_data(), indent=2))

logger.info(f"{EXPORT_PATH} written")
