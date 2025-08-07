ARG branch=latest

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS de4dot-build
WORKDIR /de4dot
RUN git clone https://github.com/GDATAAdvancedAnalytics/de4dotEx && \
    cd de4dotEx && \
    dotnet publish -c Release -f net8.0 -o publish-net8.0 --os linux --self-contained de4dot

FROM cccs/assemblyline-v4-service-base:$branch
COPY --from=de4dot-build /de4dot/de4dotEx/Release/net8.0/linux-x64 /opt/de4dot

# Python path to the service class from your service directory
ENV SERVICE_PATH=dotnet_deobfuscator.dotnet_deobfuscator.DotnetDeobfuscator

# Install apt dependencies
USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get upgrade -y && \
    # Add the Linux Software Repository for Microsoft Products
    apt-get install wget -y --no-install-recommends && \
    wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Install python dependencies
USER assemblyline
COPY requirements.txt requirements.txt
RUN pip install \
    --no-cache-dir \
    --user \
    --requirement requirements.txt && \
    rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=1.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
