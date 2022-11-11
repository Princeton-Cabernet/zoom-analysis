
P4_PROGNAME = $(shell basename $$(pwd))
P4_PROGPATH = $(shell pwd)

${SDE}/build/customer/${P4_PROGNAME}/tofino/${P4_PROGNAME}/pipe/${P4_PROGNAME}.bfa: src/${P4_PROGNAME}.p4 ${SDE}/build/customer/${P4_PROGNAME}/Makefile
	sudo $(MAKE) -C ${SDE}/build/customer/${P4_PROGNAME}
	sudo $(MAKE) install -C ${SDE}/build/customer/${P4_PROGNAME}

${SDE}/build/customer/${P4_PROGNAME}/Makefile:
	sudo mkdir -p ${SDE}/build/customer/${P4_PROGNAME} && \
	cd ${SDE}/build/customer/${P4_PROGNAME} && \
		sudo ${SDE}/pkgsrc/p4-build/configure --prefix ${SDE_INSTALL} \
		--with-tofino enable_thrift=yes \
		P4_PATH=${P4_PROGPATH}/src/${P4_PROGNAME}.p4 \
		P4_NAME=${P4_PROGNAME} P4_VERSION=p4-16
	
run-sim:
	cd ${SDE} && ./run_tofino_model.sh -p ${P4_PROGNAME} -f ${P4_PROGPATH}/config/sim_port_map.json

run-bfswitchd:
	cd ${SDE} && ./run_switchd.sh -c ${SDE_INSTALL}/share/p4/targets/tofino/${P4_PROGNAME}.conf

.PHONY: run-sim run-bfswitchd
