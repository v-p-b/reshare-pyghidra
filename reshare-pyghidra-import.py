# ReShare importer
# @author buherator
# @category _NEW_
# @keybinding
# @menupath
# @toolbar
# @runtime pyghidra
import re
import json
import logging
import sys

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------

IMPORT_PATH = "/tmp/reshare.json"
LOG_FILE = None
TYPE_IMPORT_ALLOW_RE = None # re.compile("Dummy.*")
TYPE_IMPORT_DENY_RE = None
FUNC_SYM_IMPORT_ALLOW_RE = None
FUNC_SYM_IMPORT_DENY_RE = None

# -----------------------------------------------------------------------------

logger = logging.getLogger("pyghidra-import")
handlers = [
    logging.StreamHandler(writer),
]
if LOG_FILE is not None:
    handlers.append(logging.FileHandler(LOG_FILE))

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(levelname)s](%(asctime)s) %(message)s",
    handlers=handlers,
)

logger.info("Starting import...")

from reshare import *
from reshare.helpers import *

from ghidra.program.model.address import Address, AddressSpace
from ghidra.program.model.data import (
    CategoryPath,
    ArrayDataType,
    EnumDataType,
    PointerDataType,
    StructureDataType,
    TypedefDataType,
    UnionDataType,
    VoidDataType,
    DataType,
    ParameterDefinitionImpl,
    FunctionDefinitionDataType,
    DataTypeConflictHandler,
)
from docking.widgets.filechooser import GhidraFileChooser
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import FunctionSignature

address_factory = getAddressFactory()
dtm = currentProgram.getDataTypeManager()

def _find_data_type(name: str) -> DataType:
    res = []
    for t in dtm.getAllDataTypes():
        if t.getDisplayName() == name:
            res.append(t)
    if len(res) == 0:
        return None
    elif len(res) == 1:
        return res[0]
    else:
        return res[0]


resh_data_types = {}

base_type_map = {
    "T_32PRCHAR": _find_data_type("char *"),
    "T_32PUCHAR": _find_data_type("uchar *"),
    "T_32PULONG": _find_data_type("ulong *"),
    "T_32PUQUAD": _find_data_type("PUQUAD"),
    "T_32PUSHORT": _find_data_type("ushort *"),
    "T_32PVOID": _find_data_type("void *"),
    "T_32PLONG": _find_data_type("long *"),
    "T_64PRCHAR": _find_data_type("char *"),
    "T_64PUCHAR": _find_data_type("uchar *"),
    "T_64PULONG": _find_data_type("ulong *"),
    "T_64PUQUAD": _find_data_type("PUQUAD"),
    "T_64PUSHORT": _find_data_type("ushort *"),
    "T_64PVOID": _find_data_type("void *"),
    "T_64PLONG": _find_data_type("long *"),
    "T_INT4": _find_data_type("int"),
    "T_INT8": _find_data_type("longlong"),
    "T_LONG": _find_data_type("longlong"),
    "T_QUAD": _find_data_type("longlong"),
    "T_RCHAR": _find_data_type("char"),
    "T_SHORT": _find_data_type("ushort"),
    "T_UCHAR": _find_data_type("uchar"),
    "T_UINT4": _find_data_type("uint"),
    "T_ULONG": _find_data_type("ulonglong"),
    "T_UQUAD": _find_data_type("UQUAD"),
    "T_BOOL08": _find_data_type("UQUAD"),
    "T_USHORT": _find_data_type("ushort"),
    "T_WCHAR": _find_data_type("wchar_t"),
    "T_VOID": VoidDataType(),
}

SPACE_RE = re.compile("\\s{1,}")
PTR_RE = re.compile("([^ ])\\*")

RESHARE_CATEGORY_PATH = CategoryPath("/REshare")


class ReshPyGhidraException(Exception):
    pass


def _canonize_dt_name(name: str) -> str:
    name = name.strip()
    name = SPACE_RE.sub(" ", name)
    name = PTR_RE.sub("\\1 *", name)
    return name


def resh_address_to_address(resh_addr: ReshAddress) -> Address:
    offset = int.from_bytes(bytes(resh_addr.bytes), byteorder="little", signed=False)
    address_space = address_factory.getAddressSpace(resh_addr.space)
    return address_factory.getAddress(address_space.getSpaceID(), offset)


# TODO remove
def get_ghidra_type_by_name(name: str) -> ReshDataType:
    return get_cached_ghidra_type_by_name(name, True)

def get_cached_ghidra_type_by_name(name: str, create_new=True) -> DataType:
    dt_name = _canonize_dt_name(name)
    if dt_name in base_type_map and base_type_map[dt_name] is not None:
        return base_type_map[dt_name]
    local_dt = _find_data_type(dt_name)
    if local_dt is not None:
        logger.info("Local data type found for %s, caching" % (dt_name))
        base_type_map[dt_name] = local_dt
        return local_dt
    if create_new and name in resh_data_types:
        new_type = get_ghidra_type_from_resh_type(resh_data_types[name], True)
        if new_type is not None:
            base_type_map[dt_name] = new_type
            return new_type

    return None


def get_ghidra_type_from_resh_type(T: ReshDataType, skip_cache=False) -> DataType:
    ret = None
    if not skip_cache:
        ret = get_cached_ghidra_type_by_name(T.name, False)
    if ret is None:
        ret = _find_data_type(T.name)
    if ret is not None:
        return ret
    elif T.content is None:
        return None
    elif T.content.type == "PRIMITIVE":
        name = _canonize_dt_name(T.name)
        logger.info("Adding primitive type '%s'" % (name))
        ret = None
        if T.size == 0:
            ret = TypedefDataType(RESHARE_CATEGORY_PATH, name, base_type_map["T_VOID"])
        elif T.size == 1:
            ret = TypedefDataType(RESHARE_CATEGORY_PATH, name, base_type_map["T_UCHAR"])
        elif T.size == 2:
            ret = TypedefDataType(RESHARE_CATEGORY_PATH, name, base_type_map["T_SHORT"])
        elif T.size == 4:
            ret = TypedefDataType(RESHARE_CATEGORY_PATH, name, base_type_map["T_INT4"])
        elif T.size == 8:
            ret = TypedefDataType(RESHARE_CATEGORY_PATH, name, base_type_map["T_INT8"])
        elif T.size == -1: # Exported function type
            ret = TypedefDataType(RESHARE_CATEGORY_PATH, name, base_type_map["T_INT8"])
        else:
            # raise ReshPyGhidraException("Can't handle primitive type size: %d" % (T.size))
            ret = ArrayDataType(base_type_map["T_UCHAR"], T.size)
        base_type_map[name] = ret
    elif T.content.type == "POINTER":
        name = _canonize_dt_name(T.name)
        logger.info("Adding pointer '%s'" % (name))
        pointed = base_type_map["T_VOID"]
        ret = PointerDataType(pointed, dtm)
        base_type_map[
            name
        ] = ret  # We have to cache a blank pointer to handle circular references
        pointed = None
        pointed = get_cached_ghidra_type_by_name(
            T.content.target_type.type_name,
        )  # TODO target_type vs type-reference?
        if pointed is not None:
            ret = PointerDataType(pointed, dtm)
            base_type_map[name] = ret
    elif T.content.type == "STRUCTURE":
        name = _canonize_dt_name(T.name)
        logger.info("Adding structure '%s'" % (name))
        ret = StructureDataType(RESHARE_CATEGORY_PATH, name, 0)
        base_type_map[name] = ret
        for member in T.content.members:
            member_data_type = get_ghidra_type_by_name(member.type.type_name)
            if member_data_type is not None:
                ret.add(member_data_type, member_data_type.getLength(), member.name, "")
            else:
                raise ReshPyGhidraException(
                    "Can't find structure member type: '%s' " % (member.type.type_name)
                )
    elif T.content.type == "UNION":
        name = _canonize_dt_name(T.name)
        logger.info("Adding union '%s'" % (name))
        ret = UnionDataType(RESHARE_CATEGORY_PATH, name)
        for member in T.content.members:
            if member.type.type_name in resh_data_types:
                member_data_type = resh_data_types[member.type.type_name]
                ghidra_data_type = get_ghidra_type_from_resh_type(member_data_type)
                ret.add(ghidra_data_type, ghidra_data_type.getLength(), member.name, "")
            else:
                raise ReshPyGhidraException(
                    "Can't find union member type: '%s' " % (member.type.type_name)
                )

    elif T.content.type == "ENUM":
        name = _canonize_dt_name(T.name)
        logger.info("Adding enum '%s'" % (name))
        if T.content.base_type.type_name == name:
            T.content.base_type.type_name = "void"
        base_dt = get_cached_ghidra_type_by_name(T.content.base_type.type_name)
        ret = EnumDataType(RESHARE_CATEGORY_PATH, name, T.size)
    elif T.content.type == "ARRAY":
        if T.name == T.content.base_type.type_name:
            raise ReshPyGhidraException(f"Refused to enter infinite recursion {T.name}")
        base = get_ghidra_type_by_name(T.content.base_type.type_name)
        if base is None:
            logger.warning(
                "Can't find base data type for array! %s"
                % (T.content.base_type.type_name)
            )
        else:
            ret = ArrayDataType(base, T.content.length)
    elif T.content.type == "FUNCTION":
        name = _canonize_dt_name(T.name)
        logger.info("Adding function definition '%s'" % (name))

        ret = FunctionDefinitionDataType(RESHARE_CATEGORY_PATH, name)
        if T.content.return_type is not None:
            try:
                ret_type = get_ghidra_type_by_name(T.content.return_type.type_name)
                if ret_type is not None:
                    ret.setReturnType(ret_type)
            except ReshPyGhidraException:
                logger.warning(f"Can't find return type for {T.name}")
                pass

        args = []
        if T.content.arguments is not None:
            for i, arg in enumerate(T.content.arguments):
                name = "reparam%d" % (i,)
                if arg.name is not None:
                    name = arg.name
                if arg.type.type_name == "T_NOTYPE":  # TODO PDB varargs handling
                    ret.setVarArgs(True)
                else:
                    type = get_ghidra_type_by_name(arg.type.type_name)
                    args.append(ParameterDefinitionImpl(name, type, ""))
            ret.setArguments(args)
    elif T.content.type == "LF_CLASS" or T.content.type == "LF_VTSHAPE":
        raise ReshPyGhidraException("Class handling not implemented yet")

    return ret


def import_data_types(resh: Reshare):
    for dt in resh.data_types:
        resh_data_types[dt.name] = dt
    t = dtm.startTransaction("reshare")
    for dt in resh.data_types:
        try:
            monitor.checkCancelled()
        except:
            dtm.endTransaction(t, False)
            exit()
        if (
            TYPE_IMPORT_ALLOW_RE is not None
            and TYPE_IMPORT_ALLOW_RE.fullmatch(dt.name) is None
        ) or (
            TYPE_IMPORT_DENY_RE is not None
            and TYPE_IMPORT_DENY_RE.fullmatch(dt.name) is not None
        ):
            continue
        logger.info("[*] Importing type", dt.name)
        try:
            g_dt = get_ghidra_type_from_resh_type(dt)
            if g_dt is not None:
                dtm.addDataType(g_dt, DataTypeConflictHandler.KEEP_HANDLER)
        except ReshPyGhidraException as e:
            logger.error("[-] Couln't import '%s' :(\n%s" % (dt.name, str(e)))
    dtm.endTransaction(t, True)


def import_symbols(resh: Reshare):
    for sym in resh.symbols:
        try:
            monitor.checkCancelled()
        except:
            exit()

        sym_type = None
        if sym.type is not None:
            sym_type = get_cached_ghidra_type_by_name(sym.type.type_name)
        if isinstance(sym_type, FunctionSignature):
            if (
                FUNC_SYM_IMPORT_ALLOW_RE is not None
                and FUNC_SYM_IMPORT_ALLOW_RE.fullmatch(sym.name) is None
            ) or (
                FUNC_SYM_IMPORT_DENY_RE is not None
                and FUNC_SYM_IMPORT_DENY_RE.fullmatch(sym.name) is not None
            ):
                continue
            f = getFunction(sym.name)
            if f is not None:
                logger.info("Applying function signature ", f.getName(), sym_type)
                cmd = ApplyFunctionSignatureCmd(
                    f.getEntryPoint(), sym_type, SourceType.USER_DEFINED
                )
                cmd.applyTo(currentProgram)


with open(IMPORT_PATH, "r") as input_json:
    data = json.load(input_json)
    resh = Reshare.from_json_data(data)
    import_data_types(resh)
    import_symbols(resh)
