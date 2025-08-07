"""This Assemblyline service tries to deobfuscate .Net dlls."""

import os
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection


class DotnetDeobfuscator(ServiceBase):
    """This Assemblyline service tries to deobfuscate .Net dlls."""

    def execute(self, request: ServiceRequest):
        request.result = Result()

        de4dot_output = os.path.join(self.working_directory, "de4dotoutput")
        popenargs = ["/opt/de4dot/de4dot", request.file_path, "-o", de4dot_output]
        p = subprocess.run(popenargs, capture_output=True)
        if p.returncode != 0:
            return

        obfuscators = set()
        multiple = False
        for line in p.stdout.splitlines():
            if line.startswith(b"Detected ") and line.endswith(b")"):
                # Single obfuscator detected
                obfuscator = line[9:].split(b"(", 1)[0].strip()
                if obfuscator != b"Unknown Obfuscator":
                    obfuscators.add(obfuscator.decode("UTF8", errors="backslashreplace"))
                break
            if line.startswith(b"More than one obfuscator detected"):
                multiple = True
                continue
            if multiple:
                obfuscators.add(line.split(b"(", 1)[0].strip().decode("UTF8", errors="backslashreplace"))

        if not obfuscators:
            return

        request.result.add_section(
            ResultSection(
                "DotNet Obfuscation",
                body=f"Obfuscator{'s' if len(obfuscators) > 1 else ''} detected: {', '.join(obfuscators)}",
                heuristic=Heuristic(1),
            )
        )
        request.add_extracted(name=f"{request.sha256}.de4dot", description="De4dot result", path=de4dot_output)
