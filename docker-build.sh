#/bin/sh
docker build -t seismic-reth --ssh default=$SSH_AUTH_SOCK .
