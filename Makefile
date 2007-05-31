# Binaries will land here
BINDIR=/usr/local/bin

TXT_DOC=README.txt tests.txt

CFLAGS+= -Wall ${shell pkg-config --cflags glib-2.0} ${shell libnet-config --cflags} ${shell libnet-config --defines}
GLIB=${shell pkg-config --libs glib-2.0}
ifndef LIBNET_STATIC
LIBNET=${shell libnet-config --libs}
endif
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
eb-injector: eb-injector.o ${LIBNET_STATIC}
	${CC} ${LIBNET} ${GLIB} $+ -o $@
eb-sniffer: eb-sniffer.o ${PCAP_STATIC}
	${CC} ${PCAP} $+ -o $@
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

upload:
	scp *.html *.css smok.hdtv.pl:public_html/etherbat.cryptonix.org/
