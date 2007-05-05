GLIB=-lglib-2.0
CFLAGS=-I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -Wall
LIBNET=-lnet
PCAP=-lpcap
all: injector sniffer
injector: injector.o
	${CC} ${CFLAGS} ${LIBNET} ${GLIB} $+ -o $@
sniffer: sniffer.o
	${CC} ${CFLAGS} ${PCAP} $+ -o $@
clean:
	rm -f injector.o injector sniffer.o sniffer
