cmd_/home/speedyb0y/xtun/modules.order := {   echo /home/speedyb0y/xtun/xtun-srv.ko;   echo /home/speedyb0y/xtun/xtun-clt.ko; :; } | awk '!x[$$0]++' - > /home/speedyb0y/xtun/modules.order
