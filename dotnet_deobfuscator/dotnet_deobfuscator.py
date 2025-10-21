"""This Assemblyline service tries to deobfuscate .Net dlls."""

import os
import re
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultKeyValueSection, ResultSection


class DotnetDeobfuscator(ServiceBase):
    """This Assemblyline service tries to deobfuscate .Net dlls."""

    def execute(self, request: ServiceRequest):
        request.result = Result()

        popenargs = ["/opt/dotkill/DotKill", request.file_path]
        p = subprocess.run(popenargs, capture_output=True)
        if p.returncode == 0:
            dk_section = ResultKeyValueSection("DotKill result")
            for line in p.stdout.splitlines():
                if line.startswith(b"Assembly saved") or b":" not in line:
                    break
                k, v = line.split(b":", 1)
                dk_section.set_item(
                    k.decode("UTF8", errors="backslashreplace").strip(" ."),
                    v.decode("UTF8", errors="backslashreplace").strip(),
                )
            if dk_section.body:
                request.result.add_section(dk_section)
                if os.path.exists(f"{request.file_path}_dotkill"):
                    request.add_supplementary(
                        f"{request.file_path}_dotkill", f"{request.file_path}_dotkill", "DotKill deobfuscation"
                    )

        de4dot_output = os.path.join(self.working_directory, "de4dotoutput")
        popenargs = ["/opt/de4dot/de4dot", request.file_path, "-o", de4dot_output]
        p = subprocess.run(popenargs, capture_output=True)

        if p.returncode != 0 or (
            (b"Detected " in p.stdout or b"More than one obfuscator detected" in p.stdout)
            and b"ERROR: Hmmmm... something didn't work. Try the latest version." in p.stdout
        ):

            if self.is_dotnet(request.file_contents):
                stdout_lines = b"\n".join(p.stdout.splitlines()[-20:]).decode("UTF8", errors="backslashreplace")
                stderr_lines = b"\n".join(p.stderr.splitlines()[-80:]).decode("UTF8", errors="backslashreplace")

                request.result.add_section(
                    ResultSection(
                        "De4dot Error",
                        body=(f"{stdout_lines}\n{stderr_lines}"),
                    )
                )

            return

        obfuscators = set()
        multiple = False
        for line in p.stdout.splitlines():
            if line.startswith(b"Detected ") and line.endswith(b")"):
                # Single obfuscator detected
                obfuscator = line[9:].split(b"(", 1)[0].strip()
                obfuscators.add(obfuscator.decode("UTF8", errors="backslashreplace"))
                break
            if line.startswith(b"More than one obfuscator detected"):
                multiple = True
                continue
            if multiple:
                obfuscators.add(line.split(b"(", 1)[0].strip().decode("UTF8", errors="backslashreplace"))

        if not obfuscators:
            return

        obfuscators = [obfuscator for obfuscator in obfuscators if obfuscator != "Unknown Obfuscator"]

        reported_obfuscators = []
        ignored_obfuscators = []
        zeroized_obfuscators = self.config.get("zeroized_obfuscators", [])
        if zeroized_obfuscators:
            for obfuscator in obfuscators:
                if any(re.match(x, obfuscator) for x in zeroized_obfuscators):
                    ignored_obfuscators.append(obfuscator)
                else:
                    reported_obfuscators.append(obfuscator)
        else:
            reported_obfuscators = obfuscators

        if reported_obfuscators:
            request.result.add_section(
                ResultSection(
                    "DotNet Obfuscation",
                    body=(
                        f"Obfuscator{'s' if len(reported_obfuscators) > 1 else ''} "
                        f"detected: {', '.join(reported_obfuscators)}"
                    ),
                    heuristic=Heuristic(1),
                )
            )
        if ignored_obfuscators:
            request.result.add_section(
                ResultSection(
                    "Zeroized DotNet Obfuscation",
                    body=(
                        f"Zeroized Obfuscator{'s' if len(ignored_obfuscators) > 1 else ''} "
                        f"detected: {', '.join(ignored_obfuscators)}"
                    ),
                )
            )
        request.add_extracted(name=f"{request.sha256}.de4dot", description="De4dot result", path=de4dot_output)

        return

    def is_dotnet(self, file_contents):
        MZ_OFFSET = 0x00
        MZ_SIGNATURE_OFFSET = 0x00
        MZ_PE_SIGNATURE_OFFSET = 0x3C

        MZ_SIGNATURE = b"MZ"

        PE_SIGNATURE_OFFSET = 0x00
        PE_SIZEOFOPTIONALHEADER_OFFSET = 0x14
        PE_OPTIONAL_HEADER_OFFSET = 0x18

        PE_SIGNATURE = b"PE\x00\x00"

        OPTIONAL_HEADER_MAGIC_OFFSET = 0x00

        OPTIONAL_HEADER_PE32_SIZEOFIMAGE_OFFSET = 0x38
        OPTIONAL_HEADER_PE32_NUMBER_OF_RVA_AND_SIZES_OFFSET = 0x5C
        OPTIONAL_HEADER_PE32_CLR_RUNTIME_HEADER_RVA_OFFSET = 0xD0
        OPTIONAL_HEADER_PE32_CLR_RUNTIME_HEADER_SIZE_OFFSET = 0xD4

        OPTIONAL_HEADER_PE32PLUS_SIZEOFIMAGE_OFFSET = 0x38
        OPTIONAL_HEADER_PE32PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET = 0x6C
        OPTIONAL_HEADER_PE32PLUS_CLR_RUNTIME_HEADER_RVA_OFFSET = 0xE0
        OPTIONAL_HEADER_PE32PLUS_CLR_RUNTIME_HEADER_SIZE_OFFSET = 0xE4

        OPTIONAL_HEADER_MAGIC_PE32 = 0x010B
        OPTIONAL_HEADER_MAGIC_PE32PLUS = 0x020B
        OPTIONAL_HEADER_MIN_RVA_AND_SIZES_CLR_RUNTIME_HEADER = 0x000F

        if (
            len(file_contents) > MZ_OFFSET + MZ_PE_SIGNATURE_OFFSET + 4
            and file_contents[MZ_OFFSET + MZ_SIGNATURE_OFFSET : MZ_OFFSET + MZ_SIGNATURE_OFFSET + 2] == MZ_SIGNATURE
        ):
            pe_offset = self.bytes_to_unsigned_int(file_contents, MZ_OFFSET + MZ_PE_SIGNATURE_OFFSET, 4)

            if (
                pe_offset > 0
                and len(file_contents) > pe_offset + PE_SIZEOFOPTIONALHEADER_OFFSET + 2
                and file_contents[pe_offset + PE_SIGNATURE_OFFSET : pe_offset + PE_SIGNATURE_OFFSET + 4] == PE_SIGNATURE
            ):

                size_of_optional_header = self.bytes_to_unsigned_int(
                    file_contents, pe_offset + PE_SIZEOFOPTIONALHEADER_OFFSET, 2
                )

                if (
                    size_of_optional_header > OPTIONAL_HEADER_MAGIC_OFFSET + 2
                    and len(file_contents) > pe_offset + PE_OPTIONAL_HEADER_OFFSET + size_of_optional_header
                ):
                    optional_header_magic = self.bytes_to_unsigned_int(
                        file_contents, pe_offset + PE_OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_MAGIC_OFFSET, 2
                    )

                    if (
                        optional_header_magic == OPTIONAL_HEADER_MAGIC_PE32
                        and size_of_optional_header > OPTIONAL_HEADER_PE32_CLR_RUNTIME_HEADER_SIZE_OFFSET + 4
                        and len(file_contents) > pe_offset + PE_OPTIONAL_HEADER_OFFSET + size_of_optional_header
                        and self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset + PE_OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_PE32_NUMBER_OF_RVA_AND_SIZES_OFFSET,
                            4,
                        )
                        >= OPTIONAL_HEADER_MIN_RVA_AND_SIZES_CLR_RUNTIME_HEADER
                        and 0
                        < self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset + PE_OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_PE32_SIZEOFIMAGE_OFFSET,
                            4,
                        )
                        and 0
                        < self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset + PE_OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_PE32_CLR_RUNTIME_HEADER_RVA_OFFSET,
                            4,
                        )
                        < self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset + PE_OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_PE32_SIZEOFIMAGE_OFFSET,
                            4,
                        )
                        and self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset + PE_OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_PE32_CLR_RUNTIME_HEADER_SIZE_OFFSET,
                            4,
                        )
                        > 0
                    ):

                        return True

                    if (
                        optional_header_magic == OPTIONAL_HEADER_MAGIC_PE32PLUS
                        and size_of_optional_header > OPTIONAL_HEADER_PE32PLUS_CLR_RUNTIME_HEADER_SIZE_OFFSET + 4
                        and len(file_contents) > pe_offset + PE_OPTIONAL_HEADER_OFFSET + size_of_optional_header
                        and self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset
                            + PE_OPTIONAL_HEADER_OFFSET
                            + OPTIONAL_HEADER_PE32PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET,
                            4,
                        )
                        >= OPTIONAL_HEADER_MIN_RVA_AND_SIZES_CLR_RUNTIME_HEADER
                        and 0
                        < self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset + PE_OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_PE32PLUS_SIZEOFIMAGE_OFFSET,
                            4,
                        )
                        and 0
                        < self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset
                            + PE_OPTIONAL_HEADER_OFFSET
                            + OPTIONAL_HEADER_PE32PLUS_CLR_RUNTIME_HEADER_RVA_OFFSET,
                            4,
                        )
                        < self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset + PE_OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_PE32PLUS_SIZEOFIMAGE_OFFSET,
                            4,
                        )
                        and self.bytes_to_unsigned_int(
                            file_contents,
                            pe_offset
                            + PE_OPTIONAL_HEADER_OFFSET
                            + OPTIONAL_HEADER_PE32PLUS_CLR_RUNTIME_HEADER_SIZE_OFFSET,
                            4,
                        )
                        > 0
                    ):

                        return True

        return False

    def bytes_to_unsigned_int(self, _bytes, start_offset, _len):
        return (
            int.from_bytes(_bytes[start_offset : start_offset + _len], "little", signed=False)
            if len(_bytes) > start_offset + _len
            else -1
        )
