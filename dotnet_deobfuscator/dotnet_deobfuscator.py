"""This Assemblyline service tries to deobfuscate .Net dlls."""

from assemblyline.common import forge
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result


class DotnetDeobfuscator(ServiceBase):
    """This Assemblyline service tries to deobfuscate .Net dlls."""

    def execute(self, request: ServiceRequest):
        """Run the service."""

        result = Result()
        request.result = result
