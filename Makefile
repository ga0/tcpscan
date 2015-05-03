
tcpscan: tcpscan.c
	cc tcpscan.c -lnet -lpcap -lpthread -O3 -o tcpscan `libnet-config --defines`

.PHONY: clean
clean:
	-rm -f tcpscan *.o