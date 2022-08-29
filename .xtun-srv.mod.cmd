cmd_/home/speedyb0y/xtun/xtun-srv.mod := printf '%s\n'   xtun-srv.o | awk '!x[$$0]++ { print("/home/speedyb0y/xtun/"$$0) }' > /home/speedyb0y/xtun/xtun-srv.mod
