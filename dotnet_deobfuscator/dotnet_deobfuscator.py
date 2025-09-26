"""This Assemblyline service tries to deobfuscate .Net dlls."""

import os
import re
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultKeyValueSection,
    ResultSection,
)


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
            (b"Detected " in p.stdout or b"More than one obfuscator detected" in p.stdout) and
            b"ERROR: Hmmmm... something didn't work. Try the latest version." in p.stdout):

            stdout_lines = b'\n'.join(p.stdout.splitlines()[-20:]).decode('UTF8', errors='backslashreplace')
            stderr_lines = b'\n'.join(p.stderr.splitlines()[-80:]).decode('UTF8', errors='backslashreplace')

            request.result.add_section(
                ResultSection(
                    "De4dot Error",
                    body=(
                        f"{stdout_lines}\n{stderr_lines}"
                    ),
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


