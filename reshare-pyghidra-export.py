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
from typing import Any

from reshare import *
from reshare.helpers import *

from ghidra.program.model.address import Address, AddressSpace
from javax.swing import JFileChooser
from ghidra.program.model.data import *
from ghidra.program.model.listing import Function

from jpype import JClass

# -----------------------------------------------------------------------------

LOG_FILE = None
LOG_LEVEL = logging.DEBUG
EXPORT_PATH = os.environ.get("EXPORT_PATH","/tmp/reshare.json")
SOURCE_ARCHIVE_PREFIX = ""

# -----------------------------------------------------------------------------

logger = logging.getLogger("pyghidra-export")

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

logger.info("Starting export...")

dtm = currentProgram.getDataTypeManager()


def address_to_resh(a: Address) -> ReshAddress:
    offset = int(a.getOffset())
    address_space = a.getAddressSpace()

    return ReshAddress(
        list(offset.to_bytes(8, byteorder="little", signed=False)),
        address_space.getName(),
    )


def get_function_symbols() -> list[ReshSymbol]:
    func: Function = getFirstFunction()
    ret: list[ReshSymbol] = []
    while func is not None:
        func_name = func.getName()
        func_type_name = func.getName()
        if not func_type_name.startswith("f_"):
            func_type_name = "f_%s" % (func.getName())
        func_sym = ReshSymbol(
            address=address_to_resh(func.getEntryPoint()),
            name=func_name,
            confidence=ReshSymbolConfidence.FACT,
            labels=None,
            type=ReshTypeSpec(type_name=func_type_name, embedded_type=None),
        )
        func_arguments: list[ReshFunctionArgument] = []
        for a in func.getParameters():
            # TODO create data type if missing!
            arg_type_name = a.getFormalDataType().getDisplayName()
            arg_name = a.getName()
            resh_arg = ReshFunctionArgumentPy(
                name=arg_name,
                type=ReshTypeSpec(type_name=arg_type_name, embedded_type=None),
            )
            func_arguments.append(resh_arg)

        func_type_content = ReshDataTypeContentFunctionPy(
            return_type=ReshTypeSpec(
                type_name=func.getReturn().getFormalDataType().getDisplayName(),
                embedded_type=None,
            ),
            calling_convention=func.getCallingConventionName(),
            arguments=func_arguments,
        )
        func_type = ReshDataType(
            name=func_type_name,
            size=8,
            content=func_type_content,
            modifiers=None,
        )

        RESH_TYPE_CACHE[func_type_name] = func_type
        ret.append(func_sym)
        func = getFunctionAfter(func)
    return ret


RESH_TYPE_CACHE: dict[str, ReshDataType] = {}

RESH_TYPE_CACHE["undefined"] = ReshDataType(
    name="resh_undefined",
    size=1,
    content=ReshDataTypeContentPrimitivePy(),
    modifiers=[],
)


def canonical_name(name: str) -> str:
    ret = name
    if ":" in ret:
        ret = ret.split(":")[0]
    return ret


def get_resh_data_type_from_ghidra(T: DataType) -> ReshDataType:
    T_name = canonical_name(T.getName())
    if T_name in RESH_TYPE_CACHE:
        return RESH_TYPE_CACHE[T_name]
    logger.info(f"Adding {T_name}")
    ret = ReshDataType(name=T_name, size=int(T.getLength()), content=None, modifiers=[])

    content: ReshDataTypeContent
    if T_name.startswith("undefined"):
        logger.debug("Adding array in place of Ghidra `undefined` type")
        ret.name = "resh_" + ret.name
        content = ReshDataTypeContentArrayPy(
            base_type="char", length=int(T.getLength())
        )
    elif isinstance(T, JClass("ghidra.program.database.data.StructureDB")):
        logger.debug("Adding structure type")
        members = []
        for m in T.getComponents():
            resh_member_type = get_resh_data_type_from_ghidra(m.getDataType())
            resh_member = ReshStructureMemberPy(
                name=m.getFieldName(),
                type=resh_member_type.name,
                offset=int(m.getOffset()),
            )
            members.append(resh_member)
        content = ReshDataTypeContentStructurePy(members=members)
    elif isinstance(T, JClass("ghidra.program.database.data.UnionDB")):
        logger.debug("Adding union type")
        members = []
        for m in T.getComponents():
            resh_member_type = get_resh_data_type_from_ghidra(m.getDataType())
            resh_member = ReshStructureMemberPy(
                name=m.getFieldName(),
                type=resh_member_type.name,
                offset=int(m.getOffset()),
            )
            members.append(resh_member)
        content = ReshDataTypeContentUnionPy(members=members)
    elif isinstance(T, JClass("ghidra.program.database.data.ArrayDB")):
        logger.debug("Adding array type")
        content = ReshDataTypeContentArrayPy(
            base_type=T.getDataType().getName(), length=int(T.getElementLength())
        )
    elif isinstance(T, JClass("ghidra.program.database.data.EnumDB")):

        logger.debug("Adding enum type")
        content = ReshDataTypeContentEnumPy(
            base_type="void *", members=[]
        )  # TODO Base type needs better representation
        for name in T.getNames():
            value = int(T.getValue(name))
            member = ReshEnumMember(name=name, value=value)
            content.members.append(member)
    elif isinstance(T, JClass("ghidra.program.database.data.PointerDB")):
        logger.debug("Adding pointer type")
        target_type = T.getDataType()
        target_type_name = "void"
        if target_type is not None:
            target_type_name = target_type.getName()
        content = ReshDataTypeContentPointerPy(target_type=target_type_name)
    elif isinstance(T, JClass("ghidra.program.database.data.TypedefDB")):
        target_ghidra_type=T.getDataType()
        logger.debug(f"Adding typedef to {target_ghidra_type}")
        resh_data_type=get_resh_data_type_from_ghidra(target_ghidra_type)
        content = resh_data_type.content
    else:
        logger.warning(f"Falling back to primitive type! {type(T)}")
        content = ReshDataTypeContentPrimitivePy()

    ret.content = content
    RESH_TYPE_CACHE[T_name] = ret
    return ret


def get_data_types() -> list[ReshDataType]:
    path_names = set()
    ret = []
    for dt in dtm.getAllDataTypes():
        archive_name = dt.getSourceArchive().getName()
        if not archive_name.startswith(SOURCE_ARCHIVE_PREFIX):
            continue
        path_names.add(archive_name)
        resh_dt = get_resh_data_type_from_ghidra(dt)
        if resh_dt.content is not None:
            ret.append(resh_dt)
    return ret


export = ResharePy(
    project_name=currentProgram.getExecutablePath(),
    target_md5=currentProgram.getExecutableMD5(),
)

export.symbols.extend(get_function_symbols())
get_data_types() # We ignore the return...
export.data_types.extend([v for _, v in RESH_TYPE_CACHE.items()]) # ...all types must be in cache already

logger.info(f"Exporting to: {EXPORT_PATH}")
with open(EXPORT_PATH, "w") as out:
    out.write(json.dumps(export.to_json_data(), indent=2))

logger.info(f"{EXPORT_PATH} written")
