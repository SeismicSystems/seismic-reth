#/bin/sh
DOCKER_BUILDKIT=1 docker build -t seismic-reth --ssh default=$SSH_AUTH_SOCK .
