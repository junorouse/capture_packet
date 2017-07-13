CFLAGS=-Wall
LDFLAGS=
LDLIBS=-lpcap

juno_pcap: juno_pcap.o
		"$(CC)" $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LDLIBS)

juno_pcap.o: juno_pcap.c
		"$(CC)" $(CFLAGS) -c -o "$@" "$<"


all: juno_pcap
	clean:
		rm -f juno_pcap *.o

.PHONY: all clean
