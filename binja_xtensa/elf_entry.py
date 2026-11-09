"""Register only the entry address declared by a raw Xtensa executable ELF."""
from pathlib import Path


def initialize_elf_entry(view, source):
    if view.file.has_database:
        return {"status": "preserved_database"}
    if view.arch is None or view.arch.name != "xtensa" or view.view_type != "ELF":
        return {"status": "not_xtensa_elf"}
    with Path(source).open("rb") as stream:
        header = stream.read(52)
    if (len(header) < 52 or header[:6] != b"\x7fELF\x01\x01"
            or int.from_bytes(header[16:18], "little") != 2
            or int.from_bytes(header[18:20], "little") != 94):
        return {"status": "not_executable_xtensa_elf"}
    entry = int.from_bytes(header[24:28], "little")
    segment = view.get_segment_at(entry)
    if (segment is None or not segment.executable
            or not segment.start <= entry < segment.start + segment.data_length):
        return {"status": "entry_not_in_file_backed_executable_segment", "address": entry}
    if any(function.start == entry for function in view.entry_functions):
        return {"status": "already_registered", "address": entry}
    view.add_entry_point(entry)
    return {"status": "registered_elf_entry", "address": entry}
