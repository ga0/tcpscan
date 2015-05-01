
tcpscan: tcpscan.c
	cc tcpscan.c -lnet -lpcap -o tcpscan `libnet-config --defines`

.PHONY: clean
clean:
	-rm -f tcpscan *.o