/*
  This example program provides a trivial server program that listens for TCP
  connections on port 9995.  When they arrive, it writes a short message to
  each client connection, and closes each connection once it is flushed.

  Where possible, it exits cleanly in response to a SIGINT (ctrl-c).
*/

#include "sign_verify_server.h"

static unsigned int g_index;

struct my_thread g_thread[NUM_OF_THREADS];

static const char wake[] = " ";

static const int PORT = 9995;

static void listener_cb(struct evconnlistener *, evutil_socket_t,
    struct sockaddr *, int socklen, void *);

static int set_fl(int fd, int flags)
{
	int val;
	if((val = fcntl(fd, F_GETFL, 0)) < 0)
		return -1;
	val = val|flags;
	if((val = fcntl(fd, F_SETFL, val)) < 0)
		return -1;
	return 0;
}
static int set_fd(int fd, int flags)
{
	int val;
	if((val = fcntl(fd, F_GETFD, 0)) < 0)
		return -1;
	val = val|flags;
	if((val = fcntl(fd, F_SETFD, val)) < 0)
		return -1;
	return 0;
}
static int init_queue(struct queue *q)
{
	q->front = 0;
	q->rear = 0;
	return 0;
}
static int size_queue(struct queue *q)
{
	return (q->rear - q->front + MAX_FD_NUMBER_ONE_THREAD)%MAX_FD_NUMBER_ONE_THREAD;
}
static int en_queue(struct queue *q, int fd)
{
	if ((q->rear+1)%MAX_FD_NUMBER_ONE_THREAD == q->front)
		return 1;
	q->data[q->rear] = fd;
	q->rear = (q->rear + 1)%MAX_FD_NUMBER_ONE_THREAD;
	return 0;
}
static int de_queue(struct queue *q, int *fd)
{
	if (q->rear == q->front)
		return 1;
	*fd = q->data[q->front];
	q->front = (q->front + 1)%MAX_FD_NUMBER_ONE_THREAD;
	return 0;
}
static void socket_cb(evutil_socket_t fd, short events, void *arg)
{
	int i=0;
	char recv[1024]="";
	char buf[] = "Hello World!";
	int ret = -1;
	struct event_base *base = (struct event_base *)arg;
	struct event *ev = event_base_get_running_event(base);

	zed("fd = %d, events = 0x%02x\n", fd, events);
	if ((events & EV_READ) && !(events & EV_CLOSED)) {
		ret = read(fd, recv, 1024);
		printf("********recv ret = %d********\n", ret);
		if (ret <= 0) {
			if (ev->ev_fd > 0)
				close(ev->ev_fd);
			event_free(ev);
			return;
		}
	//	for (i=0; i<ret; i++)
	//		printf("%02x ", recv[i]);
	//	printf("\n");
		ret = write(fd, buf, strlen(buf));
		zed("write ret = %d\n", ret);
	} else if (events & EV_CLOSED || events & EV_TIMEOUT) {
		zed("fd = %d, ev->ev_fd = %d\n", fd, ev->ev_fd);
		if (ev->ev_fd > 0)
			close(ev->ev_fd);
		event_free(ev);
	}
	return;
}
static void pipe_cb(evutil_socket_t fd, short event, void *arg)
{
	struct timeval tv;
	struct event *ev = NULL;
	char buf[1024];
	int pipe_bytes = 0;
	int new_fd=-1;
	int ret=-1;
	int i=0;
	int id = *(int *)arg;

	zed("thread id = %d, event = 0x%02x, fd = %d\n", id, event, fd);
	if (event & EV_READ) {
		pipe_bytes = read(fd, buf, sizeof(buf));
		zed("pipe read ret = %d\n", pipe_bytes);
		for (i=0; i<pipe_bytes; i++) {
			ret = de_queue(&g_thread[id].fd_queue, &new_fd);
			zed("de_queue ret = %d, new_fd = %d\n", ret, new_fd);
			if (ret > 0) {
				fprintf(stderr, "Could not thread %d de_queue, maybe a empty queue!\n", id);
				return;
			}
			ev = event_new(g_thread[id].base, new_fd, EV_READ|EV_PERSIST|EV_CLOSED, socket_cb, (void *)g_thread[id].base);
			evutil_timerclear(&tv);
			tv.tv_sec = 3;
			event_add(ev, &tv);
		}
	}
	return;
}
static void *thread_fun(void *arg)
{
	int id;
	struct event *ev;

	id = *(int *)arg;
	free(arg);
	pthread_detach(pthread_self());

	g_thread[id].base = event_base_new();
	if (!g_thread[id].base) {
		fprintf(stderr, "Could not initialize thread %d libevent!\n", id);
		return;
	}
	init_queue(&g_thread[id].fd_queue);
	pthread_mutex_init(&g_thread[id].lock, NULL);
	if (pipe(g_thread[id].fd) == 0) {
		if (set_fl(g_thread[id].fd[0], O_NONBLOCK)<0 || set_fl(g_thread[id].fd[1], O_NONBLOCK)<0 || set_fd(g_thread[id].fd[0], FD_CLOEXEC)<0 || set_fd(g_thread[id].fd[1], FD_CLOEXEC)<0) {
			close(g_thread[id].fd[0]);
			close(g_thread[id].fd[1]);
			g_thread[id].fd[0] = g_thread[id].fd[1] = -1;
			fprintf(stderr, "Could not set thread %d pipe FD or FL!\n", id);
			return;
		}
	zed("thread id = %d, fd[0] = %d, fd[1] = %d\n", id, g_thread[id].fd[0], g_thread[id].fd[1]);
	} else {
		fprintf(stderr, "Could not initialize thread %d pipe!\n", id);
		return;
	}
	ev = event_new(g_thread[id].base, g_thread[id].fd[0], EV_READ|EV_PERSIST, pipe_cb, (void *)&id);
	event_add(ev, NULL);
	//event_base_loop(g_thread[id].base, EVLOOP_NO_EXIT_ON_EMPTY);
	event_base_dispatch(g_thread[id].base);

	event_base_free(g_thread[id].base);
	zed("thread %d is exiting...\n", id);
}

static void listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
	int ret = -1;
	int id = -1;
next:
	id = ++g_index%NUM_OF_THREADS;
	zed("thread id = %d\n", id);
	pthread_mutex_lock(&g_thread[id].lock);
	ret = en_queue(&g_thread[id].fd_queue, fd);
	if (ret > 1) {
		printf("fd_queue of thread %d is full, try the next queue\n", id);
		pthread_mutex_unlock(&g_thread[id].lock);
		goto next;
	}
	pthread_mutex_unlock(&g_thread[id].lock);
	ret = write(g_thread[id].fd[1], wake, strlen(wake));
	zed("write ret = %d\n", ret);
}

int main(int argc, char **argv)
{
	struct evconnlistener *listener;
	struct event_base *base;

	int i, *iptr;
	struct sockaddr_in sin;

//	evthread_use_pthreads();
	bzero(&g_thread, sizeof(g_thread));

	for (i=0; i<NUM_OF_THREADS; i++) {
		iptr = (int *)calloc(1, sizeof(int));
		*iptr = i;
		if (pthread_create(&g_thread[i].id, NULL, thread_fun, (void *)iptr) != 0) {
			printf("Can't create [thread %d]\n", i);
			return 1;
		}
	}

	base = event_base_new();
	if (!base) {
		fprintf(stderr, "Could not initialize libevent!\n");
		return 2;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);

	listener = evconnlistener_new_bind(base, listener_cb, NULL,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
	    (struct sockaddr*)&sin,
	    sizeof(sin));

	if (!listener) {
		fprintf(stderr, "Could not create a listener!\n");
		return 3;
	}

	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_base_free(base);

	printf("done\n");
	return 0;
}

