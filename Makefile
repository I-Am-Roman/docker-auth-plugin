.PHONY: all binary install clean uninstall

LIBDIR=${DESTDIR}/lib/systemd/system
BINDIR=${DESTDIR}/usr/lib/docker

all: binary

binary:
	go build  -o container-authz-plugin .

install:
	mkdir -p ${LIBDIR} ${DESTDIR}
	mkdir -p ${BINDIR}/containerPolicy
	install -m 644 systemd/container-authz-plugin.service ${LIBDIR}
	install -m 644 systemd/container-authz-plugin.socket ${LIBDIR}
	install -m 755 container-authz-plugin ${BINDIR}
	install -m 644 containerPolicy/container_policy.csv ${BINDIR}/containerPolicy

clean:
	rm -f container-authz-plugin

uninstall:
	rm -f ${LIBDIR}/container-authz-plugin.service
	rm -f ${LIBDIR}/container-authz-plugin.socket
	rm -f ${BINDIR}/container-authz-plugin
	rm -f ${BINDIR}/containerPolicy/container_policy.csv
