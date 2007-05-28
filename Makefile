# Binaries will land here
BINDIR=/usr/local/bin

TXT_DOC=README.txt tests.txt

GLIB=-lglib-2.0
CFLAGS=-I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -Wall
LIBNET=-lnet
ifndef PCAP_STATIC
	PCAP=-lpcap
endif
INSTALL_BIN=install -m 755

# Tarball creation stuff
ifdef DIST_DEFINES
CHANGELOG=Changelog
FILES=${shell bzr inventory | grep -v "^.bzrignore"}
FILES+= ${TXT_DOC} ${CHANGELOG}
DIST_DIR=${shell ./etherbat --version | tr " " "-"}
endif

all: eb-injector eb-sniffer
eb-injector: eb-injector.o
	${CC} ${CFLAGS} ${LIBNET} ${GLIB} $+ -o $@
eb-sniffer: eb-sniffer.o ${PCAP_STATIC}
	${CC} ${CFLAGS} ${PCAP} $+ -o $@
install: eb-sniffer eb-injector etherbat
	${INSTALL_BIN} $+ ${BINDIR}
dev-install: eb-sniffer eb-injector etherbat
	ln -s `pwd`/eb-sniffer `pwd`/eb-injector `pwd`/etherbat ${BINDIR}
uninstall:
	rm -f ${BINDIR}/etherbat
	rm -f ${BINDIR}/eb-sniffer
	rm -f ${BINDIR}/eb-injector
clean:
	rm -f eb-injector.o eb-injector eb-sniffer.o eb-sniffer

%.txt: %.html
	links -dump $< > $@

doc: ${TXT_DOC}

changelog:
	bzr log > ${CHANGELOG}

dist:
	make real-dist DIST_DEFINES=ok
real-dist: doc changelog
	rm -rf ${DIST_DIR}
	mkdir ${DIST_DIR}
	cp ${FILES} ${DIST_DIR}
	tar zcf ${DIST_DIR}.tar.gz ${DIST_DIR}
	rm -rf ${DIST_DIR}
	gpg -ab ${DIST_DIR}.tar.gz || true
