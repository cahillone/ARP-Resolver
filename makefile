##### Makefile #####

# Chad Cahill
# eece 555
# Fall 2013


arp_resolver: arp_resolver.c
	gcc arp_resolver.c -Wall -o arp_resolver -lpcap -g
clean:
	rm arp_resolver

###################
