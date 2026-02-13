# REshare Scripts for PyGhidra

These scripts allow import/export to/from the [REshare](https://github.com/v-p-b/reshare) exchange format in Ghidra.

As these tools are highly opinionated (what data to touch, how, when...) I'm currently aiming for script-like behavior, so the code can be easily tweaked. Thus the configuration interface is currently constrants on the top of the scripts. We may change this to something more advanced, suggestions welcome! 

**Don't forget to install dependencies to your PyGhidra virtual environment:**

```
(venv) pip install .
```

Ghidra must be restarted is Python dependencies are updated for the changes to take effect.

## Notes for Ghidra

### Type Name Conflicts

Ghidra allows types of the same name to be present in multiple Typeinfo Libraries. This can result in incorrect reserialization e.g. if a fully reversed structure is overwritten with an empty one in the exported JSON due to name conflict. 

You can use the following tools to prevent/mitigate such problems:

* Use Ghidra's [conflict resolution strategies](https://scrapco.de/ghidra_docs/VERSION12/Features/Base/DataTypeManagerPlugin/data_type_manager_description.htm) to avoid duplicate names
* Use the `SOURCE_ARCHIVE_PREFIX` configuration option to only export from your primary archive

## Exporter

The exporter currently handles function symbols and data types (incl. function signatures).

Configuration variables (set as environment variables):

* `EXPORT_PATH` - Path to the export file.
* `LOG_FILE` - The console can't hold too much information so it's good to have an on-disk log to investigate any failed exports.
* `LOG_LEVEL` - Log level (use constant names from Pythons `logging`)
* `SOURCE_ARCHIVE_PREFIX` - Only export data types from data type archives starting with this string.


## Importer

The importer currently handles data types and adds them under the "REshare" category inside the current data type archive. 

The importer also loads function signatures and applies them to currently defined functions with matching names.

Configuration variables (set as environment variables):

* `EXPORT_PATH` - Path to the import file.
* `LOG_FILE` - The console can't hold too much information so it's good to have an on-disk log to investigate any failed imports.
* `LOG_LEVEL` - Log level (use constant names from Pythons `logging`)
* `TYPE_IMPORT_ALLOW_RE` - Only import types that match this regular expression (`None` to disable). 
* `TYPE_IMPORT_DENY_RE` - Don't import types that match this regular expression (`None` to disable).
* `FUNC_SYM_IMPORT_ALLOW_RE` - Only import function signatures that match this regular expression (`None` to disable).
* `FUNC_SYM_IMPORT_DENY_RE` - Don't import function signatures that match this regular expression (`None` to disable).
* `FUNC_SYM_IMPORT_ADDRESS` - Import function symbols to addresses as indicated in the REshare JSON (default `False`)

## Testing

### Unstripping (Smoke Test)

Given a binary `B` with debug symbols and its stripped version `B'` we test if `export(import(B',export(B))) == export(B)`. 

Results can be manually evaluated for now, because `export(B)` and `export(B')` are bound to differ at multiple places:

* Executable metadata (e.g. embedded symbols)
* Fallback data types
* ???

A test script is provided that starts headless ghidra and runs the import and exports on a temporary project. The script must be provided with a [sample directory](https://github.com/v-p-b/reshare/tree/main/samples/minimal-gcc) where a debug and a stripped build of the same executable are present with `..._debug` and `_stripped` file name suffices:

```
$ export GHIDRA_INSTALL_DIR=/path/to/ghidra
$ export FUNC_SYM_IMPORT_ALLOW_RE= ... # Optional configuration for importer/exporter
$ uv run tests/unstrip.py /path/to/samples/
[...test runs...]
Results saved to /tmp/randompath/
```

Evaluation is facilitated by canonicalizing the JSONs as described in RFC 8785 then applying the same formatting on both exports so line-based diffing is possible.

```
$ diff /tmp/randompath/debug_canonical.json /tmp/randompath/unstripped_canonical.json
```

