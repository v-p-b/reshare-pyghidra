# REshare Scripts for PyGhidra

These scripts allow import/export to/from the [REshare](https://github.com/v-p-b/reshare) interchange format in Ghidra.

As these tools are highly opinionated (what data to touch, how, when...) I'm currently aiming for script-like behavior, so the code can be easily tweaked. Thus the configuration interface is currently constrants on the top of the scripts. We may change this to something more advanced, suggestions welcome! 

**Don't forget to install dependencies to your PyGhidra virtual environment:**

```
(venv) pip install -r requirements.txt
```

Ghidra must be restarted is Python dependencies are updated for the changes to take effect.


## Exporter

The exporter currently handles function symbols and data types (incl. function signatures).

Configuration variables:

* `EXPORT_PATH` - Path to the export file.
* `LOG_FILE` - The console can't hold too much information so it's good to have an on-disk log to investigate any failed exports.
* `SOURCE_ARCHIVE_PREFIX` - Only export data types from data type archives starting with this string.


## Importer

The importer currently handles data types and adds them under the "REshare" category inside the current data type archive. 

The importer also loads function signatures and applies them to currently defined functions with matching names.

Configuration variables:

* `EXPORT_PATH` - Path to the import file.
* `LOG_FILE` - The console can't hold too much information so it's good to have an on-disk log to investigate any failed imports.
* `TYPE_IMPORT_ALLOW_RE` - Only import types that match this regular expression (`None` to disable). 
* `TYPE_IMPORT_DENY_RE` - Don't import types that match this regular expression (`None` to disable).
* `FUNC_SYM_IMPORT_ALLOW_RE` - Only import function signatures that match this regular expression (`None` to disable).
* `FUNC_SYM_IMPORT_DENY_RE` = Don't import function signatures that match this regular expression (`None` to disable).


