

miner: miner.c tls.c tls.h
	$(CC) $^ -o $@ -lssl -lcrypto -levent
