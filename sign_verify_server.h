#ifndef __SIGN_VERIFY_SERVER__
#define __SIGN_VERIFY_SERVER__
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h>

//#include <test_lib.h>
#ifndef SIGN_AND_VERIFY_SERVER
#define SIGN_AND_VERIFY_SERVER
#endif
#include <macro.h>
#include <structure.h>
#include </root/zed/libevent-2.1.10-stable/event-internal.h>
#include <event2/event-config.h>
#include <event2/event_struct.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/thread.h>

#define ZEDD
#ifdef ZEDD
#define zed(format, args...) printf("[%s][%s][%d] "format"", __FILE__, __func__, __LINE__, ##args)
#else
#define zed(format, args...)
#endif
#define NUM_OF_THREADS 6
#define MAX_FD_NUMBER_ONE_THREAD 1024

struct queue {
	int data[MAX_FD_NUMBER_ONE_THREAD];
	int front, rear;
};
struct my_thread {
	pthread_t id;
	struct event_base *base;
	int fd[2];
	struct queue fd_queue;
	pthread_mutex_t lock;
};
#endif
