# Binaries will land here
BINDIR=/usr/local/bin

GLIB=-lglib-2.0
CFLAGS=-I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -Wall
LIBNET=-lnet
PCAP=-lpcap
INSTALL_BIN=install -m 755

all: eb-injector eb-sniffer
eb-injector: eb-injector.o
	${CC} ${CFLAGS} ${LIBNET} ${GLIB} $+ -o $@
eb-sniffer: eb-sniffer.o
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
