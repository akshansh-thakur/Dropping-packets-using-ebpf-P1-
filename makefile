
CLANG ?= clang
CC ?= gcc

all: drop.bpf.o loader

drop.bpf.o: drop.bpf.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

loader: loader.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf -lz

clean:
	rm -f drop.bpf.o loader
