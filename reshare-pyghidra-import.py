# ReShare importer
# @author buherator
# @category _NEW_
# @keybinding
# @menupath
# @toolbar
# @runtime pyghidra
import json
import logging
import os
import sys

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
try:
    from ghidra.ghidra_builtins import createFunction, getFunctionAt, getFunction, monitor, currentProgram, \
    getFirstFunction, getFunctionAfter, writer
except ImportError:
    pass
from ghidra.program.model.address import Address
from ghidra.program.model.data import DataType
from ghidra.program.model.listing import Function, FunctionSignature
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException
from reshare import Reshare, ReshDataType
from reshare_pyghidra import ReshGhidraImporter, ReshGhidraSymbol, ReshPyGhidraException, _canonize_sym_name

# from ghidra.ghidra_builtins import getFunctionAt, createFunction, getFunction

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------

IMPORT_PATH = os.environ.get("IMPORT_PATH","/tmp/reshare.json")
LOG_FILE = None
LOG_LEVEL = logging.DEBUG
TYPE_IMPORT_ALLOW_RE = None  # re.compile("Dummy.*")
TYPE_IMPORT_DENY_RE = None
FUNC_SYM_IMPORT_ALLOW_RE = None
FUNC_SYM_IMPORT_DENY_RE = None
IMPORT_MODE= os.environ.get("IMPORT_MODE","name") # "name" or "address"

# -----------------------------------------------------------------------------

logger=logging.getLogger()

log_handlers = [
    logging.StreamHandler(writer),
]

if LOG_FILE is not None:
    log_handlers.append(logging.FileHandler(LOG_FILE))

log_fmt = logging.Formatter("[%(levelname)s](%(asctime)s) %(message)s")
logger.handlers.clear()
logger.setLevel(LOG_LEVEL)
for h in log_handlers:
    h.setLevel(LOG_LEVEL)
    h.setFormatter(log_fmt)
    logger.addHandler(h)


def type_filter_cb(dt: ReshDataType) -> bool:
    if (
            TYPE_IMPORT_ALLOW_RE is not None
            and TYPE_IMPORT_ALLOW_RE.fullmatch(dt.name) is None
    ) or (
            TYPE_IMPORT_DENY_RE is not None
            and TYPE_IMPORT_DENY_RE.fullmatch(dt.name) is not None
    ):
        return False
    return True


def set_function_signature_by_address(addr: Address, ghidra_type: DataType):
    cmd = ApplyFunctionSignatureCmd(
        addr, ghidra_type, SourceType.USER_DEFINED
    )
    cmd.applyTo(currentProgram)

def main():
    importer = ReshGhidraImporter(currentProgram, IMPORT_PATH, monitor)
    importer.add_data_type_filter(type_filter_cb)
    importer.import_resh()
    f = getFirstFunction()
    while f is not None:
        sym_data: None|ReshGhidraSymbol=None
        if IMPORT_MODE == "address":
            logger.info(f"Import by address {f.getName()}")
            sym_data=importer.get_symbol_by_address(f.getEntryPoint().getOffset())
            if sym_data is not None:
                f.setName(_canonize_sym_name(sym_data.name), SourceType.USER_DEFINED)
        elif IMPORT_MODE == "name":
            logger.info(f"Import by name {f.getName()}")
            sym_data = importer.get_symbol_by_name(f.getName())
        else:
            raise ReshPyGhidraException("Invalid import mode")

        if sym_data is not None:
            set_function_signature_by_address(f.getEntryPoint(), sym_data.ghidra_type)
            print(f"Function at {f.getEntryPoint().getOffset():X}: {sym_data.name}")
        else:
            logger.error(f"Can't find symbol data for {f.getName()}")

        f=getFunctionAfter(f)

if __name__ == "__main__":
    main()