import sys
import pyghidra, jpype
import tempfile
import os
import json
import rfc8785

pyghidra.start()

target_dir=sys.argv[1]

with tempfile.TemporaryDirectory(delete=False) as project_dir:
    reshare_path=os.path.join(project_dir, "reshare.json")
    os.environ["IMPORT_PATH"]=reshare_path
    os.environ["EXPORT_PATH"]=reshare_path
    with pyghidra.open_project(project_dir, "TestProject", create=True) as project:
        loader = pyghidra.program_loader().project(project)
        p_debug = None
        p_stripped = None
        for f in os.listdir(target_dir):
            full_path = os.path.join(target_dir, f)
            if os.path.isfile(full_path) and ("_debug" in f or "_stripped" in f):
                if "_debug" in f:
                    assert p_debug is None
                    p_debug = f
                if "_stripped" in f:
                    assert p_stripped is None
                    p_stripped = f
                loader = loader.source(full_path).projectFolderPath("/")
                with loader.load() as load_results:
                    load_results.save(pyghidra.task_monitor())
        with pyghidra.program_context(project, f"/{p_debug}") as program:
            pyghidra.analyze(program, pyghidra.task_monitor(30))
            program.save("Analyzed", pyghidra.task_monitor())
            pyghidra.ghidra_script(
                os.path.join(
                    os.getcwd(), "reshare-pyghidra-export.py"
                ),
                project,
                program,
            )
            json_debug = json.load(open(reshare_path, "r"))
            with open(
                os.path.join(project_dir, "debug_canonical.json"), "w"
            ) as _io:
                j=json.loads(rfc8785.dumps(json_debug))
                json.dump(j, _io, indent=2)
        with pyghidra.program_context(project, f"/{p_stripped}") as program:
            pyghidra.analyze(program, pyghidra.task_monitor(30))
            program.save("Analyzed", pyghidra.task_monitor())
            pyghidra.ghidra_script(
                os.path.join(
                    os.getcwd(), "reshare-pyghidra-import.py"
                ),
                project,
                program,
            )
            pyghidra.ghidra_script(
                os.path.join(
                    os.getcwd(), "reshare-pyghidra-export.py"
                ),
                project,
                program,
            )
            json_stripped = json.load(open(reshare_path, "r"))
            with open(
                os.path.join(project_dir, "unstripped_canonical.json"), "w"
            ) as _io:
                j=json.loads(rfc8785.dumps(json_stripped))
                json.dump(j, _io, indent=2)
        del os.environ["IMPORT_PATH"]
        del os.environ["EXPORT_PATH"]
        print(f"Results saved to {project_dir}")