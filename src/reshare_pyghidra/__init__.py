import json
import logging
import re
from typing import Callable, Generator

from ghidra.util.task import TaskMonitor

from ghidra.util.exception import DuplicateNameException, CancelledException

from ghidra.program.model.address import Address, AddressSpace
from ghidra.program.model.data import (
    ArrayDataType,
    CategoryPath,
    DataType,
    DataTypeConflictHandler,
    EnumDataType,
    FunctionDefinitionDataType,
    ParameterDefinitionImpl,
    PointerDataType,
    StructureDataType,
    TypedefDataType,
    UnionDataType,
    VoidDataType,
)
from ghidra.program.model.listing import Function, FunctionSignature, Program
from ghidra.program.model.symbol import SourceType, Symbol
from jpype import JClass
from reshare import *
from reshare.helpers import *
from dataclasses import dataclass


logger = logging.getLogger("resh-pyghidra-lib")

SPACE_RE = re.compile("\\s{1,}")
PTR_RE = re.compile("([^ ])\\*")

RESHARE_CATEGORY_PATH = CategoryPath("/REshare")


@dataclass
class ReshGhidraSymbol:
    name: str
    address: int
    ghidra_type: DataType
    resh_symbol: ReshSymbol


class ReshPyGhidraException(Exception):
    pass


def _canonize_dt_name(name: str) -> str:
    name = name.strip()
    name = SPACE_RE.sub(" ", name)
    name = PTR_RE.sub("\\1 *", name)
    return name


def _canonize_sym_name(name: str) -> str:
    name = name.strip()
    name = SPACE_RE.sub("_", name)
    return name


class ReshGhidraImporter(object):
    def __init__(self, program: Program, json_path: str, monitor: TaskMonitor):
        self.program = program
        self.monitor = monitor
        self.address_factory = program.getAddressFactory()
        self.dtm = program.getDataTypeManager()

        with open(json_path, "r") as input_json:
            data = json.load(input_json)
            self.resh = Reshare.from_json_data(data)

        self._ghidra_symbol_map_address: dict[int, ReshGhidraSymbol] = {}
        self._ghidra_symbol_map_name: dict[str, ReshGhidraSymbol] = {}

        self.resh_data_types = {}
        self.base_type_map = {
            "T_32PRCHAR": self._find_data_type("char *"),
            "T_32PUCHAR": self._find_data_type("uchar *"),
            "T_32PULONG": self._find_data_type("ulong *"),
            "T_32PUQUAD": self._find_data_type("PUQUAD"),
            "T_32PUSHORT": self._find_data_type("ushort *"),
            "T_32PVOID": self._find_data_type("void *"),
            "T_32PLONG": self._find_data_type("long *"),
            "T_64PRCHAR": self._find_data_type("char *"),
            "T_64PUCHAR": self._find_data_type("uchar *"),
            "T_64PULONG": self._find_data_type("ulong *"),
            "T_64PUQUAD": self._find_data_type("PUQUAD"),
            "T_64PUSHORT": self._find_data_type("ushort *"),
            "T_64PVOID": self._find_data_type("void *"),
            "T_64PLONG": self._find_data_type("long *"),
            "T_INT4": self._find_data_type("int"),
            "T_INT8": self._find_data_type("longlong"),
            "T_LONG": self._find_data_type("longlong"),
            "T_QUAD": self._find_data_type("longlong"),
            "T_RCHAR": self._find_data_type("char"),
            "T_SHORT": self._find_data_type("ushort"),
            "T_UCHAR": self._find_data_type("uchar"),
            "T_CHAR": self._find_data_type("char"),
            "T_UINT4": self._find_data_type("uint"),
            "T_ULONG": self._find_data_type("ulonglong"),
            "T_UQUAD": self._find_data_type("UQUAD"),
            "T_BOOL08": self._find_data_type("UQUAD"),
            "T_USHORT": self._find_data_type("ushort"),
            "T_WCHAR": self._find_data_type("wchar_t"),
            "T_VOID": VoidDataType(),
        }
        self._symbol_filters: list[Callable[[ReshSymbol], bool]] = []
        self._data_type_filters: list[Callable[[ReshDataType], bool]] = []

    def _find_data_type(self, name: str) -> DataType:
        res = []
        for t in self.dtm.getAllDataTypes():
            if t.getDisplayName() == name:
                res.append(t)
        if len(res) == 0:
            return None
        elif len(res) == 1:
            return res[0]
        else:
            return res[0]

    def resh_address_to_address(self, resh_addr: ReshAddress) -> Address:
        offset = int.from_bytes(
            bytes(resh_addr.bytes), byteorder="little", signed=False
        )
        address_space = self.address_factory.getAddressSpace(resh_addr.space)
        if address_space is None:
            address_space = self.address_factory.getDefaultAddressSpace()
        return self.address_factory.getAddress(address_space.getSpaceID(), offset)

    def import_resh(self):
        self._import_data_types()
        self._import_symbols()

    def add_symbol_filter(self, filt: Callable[[ReshSymbol], bool]):
        self._symbol_filters.append(filt)

    def add_data_type_filter(self, filt: Callable[[ReshDataType], bool]):
        self._data_type_filters.append(filt)

    def clear_data_type_filters(self):
        self._data_type_filters.clear()

    def clear_symbol_filters(self):
        self._symbol_filters.clear()

    def get_cached_ghidra_type_by_name(
        self, name: str, create_new=True
    ) -> DataType | None:
        logger.debug(f"Looking up cached type: {name}")
        dt_name = _canonize_dt_name(name)
        if dt_name in self.base_type_map and self.base_type_map[dt_name] is not None:
            return self.base_type_map[dt_name]
        local_dt = self._find_data_type(dt_name)
        if local_dt is not None:
            logger.info("Local data type found for %s, caching" % (dt_name))
            self.base_type_map[dt_name] = local_dt
            return local_dt
        if create_new and name in self.resh_data_types:
            new_type = self.get_ghidra_type_from_resh_type(
                self.resh_data_types[name], True
            )
            if new_type is not None:
                self.base_type_map[dt_name] = new_type
                return new_type

        return None

    def get_ghidra_type_from_resh_type(
        self, T: ReshDataType, skip_cache=False
    ) -> DataType | None:
        ret = None
        if not skip_cache:
            ret = self.get_cached_ghidra_type_by_name(T.name, False)
        if ret is None:
            ret = self._find_data_type(T.name)
        if ret is not None:
            return ret
        elif T.content is None:
            return None
        elif T.content.type == "PRIMITIVE":
            name = _canonize_dt_name(T.name)
            logger.info("Adding primitive type '%s'" % (name))
            ret = None
            try:
                if T.size < 1:
                    ret = TypedefDataType(
                        RESHARE_CATEGORY_PATH, name, self.base_type_map["T_VOID"]
                    )
                elif T.size == 1:
                    ret = TypedefDataType(
                        RESHARE_CATEGORY_PATH, name, self.base_type_map["T_UCHAR"]
                    )
                elif T.size == 2:
                    ret = TypedefDataType(
                        RESHARE_CATEGORY_PATH, name, self.base_type_map["T_SHORT"]
                    )
                elif T.size == 4:
                    ret = TypedefDataType(
                        RESHARE_CATEGORY_PATH, name, self.base_type_map["T_INT4"]
                    )
                elif T.size == 8:
                    ret = TypedefDataType(
                        RESHARE_CATEGORY_PATH, name, self.base_type_map["T_INT8"]
                    )
                elif T.size == -1:  # Exported function type
                    ret = TypedefDataType(
                        RESHARE_CATEGORY_PATH, name, self.base_type_map["T_INT8"]
                    )
            except Exception as e:
                logger.error(f"Couldn't map basic type for length {T.size}")
            if ret is None:
                # raise ReshPyGhidraException("Can't handle primitive type size: %d" % (T.size))
                ret = ArrayDataType(self.base_type_map["T_CHAR"], T.size)
            self.base_type_map[name] = ret
        elif T.content.type == "POINTER":
            name = _canonize_dt_name(T.name)
            logger.info("Adding pointer '%s'" % (name))
            pointed = self.base_type_map["T_VOID"]
            ret = PointerDataType(pointed, self.dtm)
            self.base_type_map[name] = (
                ret  # We have to cache a blank pointer to handle circular references
            )
            pointed = None
            pointed = self.get_cached_ghidra_type_by_name(
                T.content.target_type.type_name,
            )  # TODO target_type vs type-reference?
            if pointed is not None:
                ret = PointerDataType(pointed, self.dtm)
                self.base_type_map[name] = ret
        elif T.content.type == "STRUCTURE":
            name = _canonize_dt_name(T.name)
            logger.info("Adding structure '%s'" % (name))
            ret = StructureDataType(RESHARE_CATEGORY_PATH, name, 0)
            self.base_type_map[name] = ret
            for member in T.content.members:
                # member_data_type = self.get_ghidra_type_by_name(member.type.type_name)
                member_data_type = self.get_cached_ghidra_type_by_name(
                    member.type.type_name
                )
                if member_data_type is not None:
                    ret.add(
                        member_data_type, member_data_type.getLength(), member.name, ""
                    )
                else:
                    raise ReshPyGhidraException(
                        "Can't find structure member type: '%s' "
                        % (member.type.type_name)
                    )
        elif T.content.type == "UNION":
            name = _canonize_dt_name(T.name)
            logger.info("Adding union '%s'" % (name))
            ret = UnionDataType(RESHARE_CATEGORY_PATH, name)
            for member in T.content.members:
                if member.type.type_name in self.resh_data_types:
                    member_data_type = self.resh_data_types[member.type.type_name]
                    ghidra_data_type = self.get_ghidra_type_from_resh_type(
                        member_data_type
                    )
                    ret.add(
                        ghidra_data_type, ghidra_data_type.getLength(), member.name, ""
                    )
                else:
                    raise ReshPyGhidraException(
                        "Can't find union member type: '%s' " % (member.type.type_name)
                    )

        elif T.content.type == "ENUM":
            name = _canonize_dt_name(T.name)
            logger.info("Adding enum '%s'" % (name))
            if T.content.base_type.type_name == name:
                T.content.base_type.type_name = "void"
            base_dt = self.get_cached_ghidra_type_by_name(T.content.base_type.type_name)
            ret = EnumDataType(RESHARE_CATEGORY_PATH, name, T.size)
        elif T.content.type == "ARRAY":
            if T.name == T.content.base_type.type_name:
                raise ReshPyGhidraException(
                    f"Refused to enter infinite recursion {T.name}"
                )
            # base = get_ghidra_type_by_name(T.content.base_type.type_name)
            base = self.get_cached_ghidra_type_by_name(T.content.base_type.type_name)
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
                    ret_type = self.get_cached_ghidra_type_by_name(
                        T.content.return_type.type_name
                    )
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
                        type = self.get_cached_ghidra_type_by_name(arg.type.type_name)
                        args.append(ParameterDefinitionImpl(name, type, ""))
                ret.setArguments(args)
        elif T.content.type == "LF_CLASS" or T.content.type == "LF_VTSHAPE":
            raise ReshPyGhidraException("Class handling not implemented yet")

        return ret

    def _import_data_types(self):
        for dt in self.resh.data_types:
            self.resh_data_types[dt.name] = dt

        t = self.dtm.startTransaction("reshare")

        for dt in self.resh.data_types:
            try:
                self.monitor.checkCancelled()
            except CancelledException:
                self.dtm.endTransaction(t, False)
                break

            skip = False
            for f in self._data_type_filters:
                if not f(dt):
                    skip = True
                    break
            if skip:
                continue
            logger.info(f"[*] Importing type {dt.name}")
            try:
                local_type = self.get_ghidra_type_from_resh_type(dt)
                self.base_type_map[dt.name] = local_type
            except ReshPyGhidraException as e:
                logger.error(
                    "[-] Couldn't import '%s' :(\n>> %s <<" % (dt.name, str(e))
                )
                # self.dtm.endTransaction(t, False)
                # raise

        self.dtm.endTransaction(t, True)

    def _map_symbol(self, map_sym: ReshGhidraSymbol):
        self._ghidra_symbol_map_address[map_sym.address] = map_sym
        self._ghidra_symbol_map_name[map_sym.name] = map_sym

    def _import_symbols(self):
        for sym in self.resh.symbols:
            if sym.type is None:
                continue
            skip = False
            for f in self._symbol_filters:
                if not f(sym):
                    skip = True
                    break
            if skip:
                continue
            resh_type = self.resh_data_types[sym.type.type_name]
            if sym.type.type_name not in self.base_type_map:
                logger.warning(f"Can't find {sym.type.type_name}")
                continue
            local_type = self.base_type_map[sym.type.type_name]
            sym_address = self.resh_address_to_address(sym.address)
            if local_type is None:
                logger.warning(f"Symbols Ghidra type is None ({sym.type.type_name})")
                continue
            else:
                self._map_symbol(
                    ReshGhidraSymbol(
                        name=sym.name,
                        address=sym_address.getOffset(),
                        ghidra_type=local_type,
                        resh_symbol=sym,
                    )
                )

    def get_symbol_by_name(self, name: str) -> ReshGhidraSymbol | None:
        if name in self._ghidra_symbol_map_name:
            return self._ghidra_symbol_map_name[name]
        else:
            return None

    def get_symbol_by_address(self, address: int) -> ReshGhidraSymbol | None:
        if address in self._ghidra_symbol_map_address:
            return self._ghidra_symbol_map_address[address]
        else:
            return None

    def get_symbols(self) -> Generator[ReshGhidraSymbol, None, None]:
        for _, item in self._ghidra_symbol_map_name.items():
            yield item


def address_to_resh(a: Address) -> ReshAddress:
    offset = int(a.getOffset())
    address_space = a.getAddressSpace()

    return ReshAddress(
        list(offset.to_bytes(8, byteorder="little", signed=False)),
        address_space.getName(),
    )


def canonical_name(name: str) -> str:
    ret = name
    if ":" in ret:
        ret = ret.split(":")[0]
    return ret


class ReshGhidraExporter(object):
    def __init__(self, program: Program):
        self.program = program
        self.dtm = program.getDataTypeManager()

        self.resh_type_cache: dict[str, ReshDataType] = {
            "undefined": ReshDataType(
                name="resh_undefined",
                size=1,
                content=ReshDataTypeContentPrimitivePy(),
                modifiers=[],
            )
        }

        self._symbol_filters: list[Callable[[Symbol], bool]] = []
        self._data_type_filters: list[Callable[[DataType], bool]] = []

    def add_symbol_filter(self, filt: Callable[[Symbol], bool]):
        self._symbol_filters.append(filt)

    def add_data_type_filter(self, filt: Callable[[DataType], bool]):
        self._data_type_filters.append(filt)

    def clear_data_type_filters(self):
        self._data_type_filters.clear()

    def clear_symbol_filters(self):
        self._symbol_filters.clear()

    def export(self) -> Reshare:
        export = ResharePy(
            project_name=self.program.getExecutablePath(),
            target_md5=self.program.getExecutableMD5(),
        )
        export.symbols.extend(self.get_function_symbols())
        _ = self.get_data_types()
        export.data_types.extend(
            [v for _, v in self.resh_type_cache.items()]
        )  # ...all types must be in cache already
        return export

    def get_function_symbols(self) -> list[ReshSymbol]:
        ret: list[ReshSymbol] = []
        func_iter = self.program.getFunctionManager().getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
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
            self.resh_type_cache[func_type_name] = func_type
            ret.append(func_sym)
            # func = self.program.getFunctionAfter(func)
        return ret

    def get_resh_data_type_from_ghidra(self, T: DataType) -> ReshDataType:
        T_name = canonical_name(T.getName())
        if T_name in self.resh_type_cache:
            return self.resh_type_cache[T_name]
        logger.info(f"Adding {T_name}")
        ret = ReshDataType(
            name=T_name, size=int(T.getLength()), content=None, modifiers=[]
        )

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
                resh_member_type = self.get_resh_data_type_from_ghidra(m.getDataType())
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
                resh_member_type = self.get_resh_data_type_from_ghidra(m.getDataType())
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
            target_ghidra_type = T.getDataType()
            logger.debug(f"Adding typedef to {target_ghidra_type}")
            resh_data_type = self.get_resh_data_type_from_ghidra(target_ghidra_type)
            content = resh_data_type.content
        else:
            logger.warning(f"Falling back to primitive type! {type(T)}")
            content = ReshDataTypeContentPrimitivePy()

        ret.content = content
        self.resh_type_cache[T_name] = ret
        return ret

    def get_data_types(self) -> list[ReshDataType]:
        ret = []
        for dt in self.dtm.getAllDataTypes():
            filtered = False
            for dt_filter in self._data_type_filters:
                if not dt_filter(dt):
                    filtered = True
                    break
            if filtered:
                continue

            resh_dt = self.get_resh_data_type_from_ghidra(dt)
            if resh_dt.content is not None:
                ret.append(resh_dt)
        return ret
