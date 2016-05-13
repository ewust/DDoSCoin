

miner: miner.c tls.c tls.h
	$(CC) $^ -o $@ -O3 -lssl -lcrypto -levent
