packet: packet.o
	gcc -o packet packet.o -lpcap
packet.o: packet.c
	gcc -c packet.c
