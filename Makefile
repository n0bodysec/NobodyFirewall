all:
	gcc nfwall.c -o nfwall -pthread -lpcap

clean:
	$(RM) nfwall