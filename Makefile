all:
	gcc -lpcap -lpthread nfwall.c -o nfwall

clean:
	$(RM) nfwall