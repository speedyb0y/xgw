cmd_/home/speedyb0y/xtun/xtun-clt.mod := printf '%s\n'   xtun-clt.o | awk '!x[$$0]++ { print("/home/speedyb0y/xtun/"$$0) }' > /home/speedyb0y/xtun/xtun-clt.mod
