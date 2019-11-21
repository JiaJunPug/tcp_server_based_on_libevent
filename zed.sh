#!/bin/bash
#gcc -g server.c -o server -I/root/zed/opensource/libevent-2.1.10-stable -levent_core -levent_pthreads -lpthread
#gcc test.c -lpthread -o a.out
gcc -g server.c -o a -I/root/zed/include -I/opt/svs/dependency/lib/include/ -L/opt/svs/dependency/lib/ -levent_core -levent_pthreads -lpthread
