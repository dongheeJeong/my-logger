/**
 * File              : mfcore-logger.c
 * Author            : Donghee Jeong <donghee950403@gmail.com>
 * Date              : 2019.09.16
 * Last Modified Date: 2019.09.16
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <fcntl.h>
#include <string.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>

#include <syslog.h>
#include <sys/resource.h>
#include <signal.h>

#define LOG_DIR		"./"
#define LOG_FILE	LOG_DIR"log.out"
#define PROC_NAME	"logger"
#define SOCK_NAME	"/tmp/c-logger.sock"
#define BACK_LOG	128
#define BUF_SIZE	1024

int num_accept;
pthread_mutex_t mutex, mutex2;
typedef struct {
	int sockfd_clnt;
	int fd_log;
} thread_param_t;

void debug(const char *msg, ...)
{
	va_list args;
	va_start(args, msg);
#ifndef DEBUG
	vsyslog(LOG_ERR, msg, args);
#else
	vfprintf(stderr, msg, args);
#endif
	va_end(args);
	return;
}

thread_param_t * new_param(int sockfd_clnt, int fd_log)
{
	thread_param_t *param;

	param = malloc(sizeof(thread_param_t));
	if (!param) {
		debug("malloc() error: %s.", strerror(errno));
		exit(1);
	}

	param->sockfd_clnt	= sockfd_clnt;
	param->fd_log		= fd_log;
	return param;
}

int init_unix_sock(void)
{
	int sockfd;
	struct sockaddr_un serv_addr;

	sockfd = socket(PF_LOCAL, SOCK_STREAM, 0);

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strcpy(serv_addr.sun_path, SOCK_NAME);

	if (access(SOCK_NAME, F_OK) == 0)
		unlink(SOCK_NAME);

	if (bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
		debug("bind() error: %s.", strerror(errno));
		exit(1);
	}

	if (listen(sockfd, BACK_LOG) < 0) {
		debug("listen() error: %s.", strerror(errno));
		exit(1);
	}

	return sockfd;
}

int init_log_file(void)
{
	int fd_log;

	/* check log dir exists */
	if (access(LOG_DIR, F_OK) < 0 && mkdir(LOG_DIR, 0755) < 0) {
		debug("mkdir() error: %s.", strerror(errno));
		exit(1);
	}

	/* open log file which will be shared between threads */
	if ((fd_log = open(LOG_FILE, O_WRONLY|O_CREAT|O_APPEND, 0644)) < 0) {
		debug("open() error: %s.", strerror(errno));
		exit(1);
	}

	return fd_log;
}

void * write_log(void * params)
{
	thread_param_t *p = (thread_param_t*) params;
	char msg[BUF_SIZE], *base, *ptr;
	ssize_t len_read, len_write;
	size_t len_s;

	pthread_mutex_lock(&mutex);

	/**
	 * read되는 msg가 '\n'를 delimeter로 문장 단위로 나누어져 전송됨을 가정
	 * msg = 문장1\n문장2\n문장3\n ...
	 */
	while ((len_read = read(p->sockfd_clnt, msg, BUF_SIZE-1)) > 0) {
		msg[len_read] = '\n';

		/* read한 message를 개행문자 단위로 write한다. */
		/* 이는 로그가 한 라인 단위로 찍히는 것처럼 보이도록 하기 위함임 */
		ptr = msg;
		do {
			/* 연속된 개행문자 무시 */
			while (ptr < &msg[len_read] && *ptr == '\n')
				++ptr;

			base = ptr;
			len_s = 0;

			/* 한 문장의 길이 측정 (len_s) */
			while (ptr < &msg[len_read] && *ptr != '\n')
				++ptr, ++len_s;

			++ptr, ++len_s; /* 문장의 마지막에 1개의 개행문자를 포함하기 위한 증가 */

#ifndef DEBUG
			if (write(p->fd_log, base, len_s) < 0) {
#else
			if (write(STDOUT_FILENO, base, len_s) < 0) {
#endif
				debug("write() error: %s.", strerror(errno));
				pthread_mutex_unlock(&mutex);
				goto EXIT;
			}

#ifndef DEBUG
			/* Write a sentence with no buffering. */
			fsync(p->fd_log);
#endif

			/* 로그가 찍히는 시각적 효과를 위해 잠시 숙면 */
			usleep(5000);
		} while (ptr < &msg[len_read]);
	}

	if (len_read < 0) {
		debug("read() error: %s", strerror(errno));
		pthread_mutex_unlock(&mutex);
	}
	pthread_mutex_unlock(&mutex);

EXIT:
	close(p->sockfd_clnt);
	free(p);

	pthread_mutex_lock(&mutex2);
	--num_accept;
	pthread_mutex_unlock(&mutex2);

	return NULL;
}

void daemonize(void)
{
	pid_t pid;
	int i, fd0, fd1, fd2;
	struct rlimit		rl;
	struct sigaction	sa;

	/* Clear file creation mask. */
	umask(0);

	/* Get maximum number of file descriptos. */
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
		debug("getrlimit() error: %s.", strerror(errno));
		exit(1);
	}

	/*
	 * Guarantee that the child is not a process group leader.
	 * Also, prerequisite for the call to setsid().
	 */
	if ((pid = fork()) < 0) {
		debug("fork() error: %s.", strerror(errno));
		exit(1);
	} else if (pid != 0) /* parent */ {
		exit(0);
	}
	setsid();

	/* Ensure future opens won't allocate controlling TTY. */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		debug("sigaction() error: %s.", strerror(errno));
		exit(1);
	}

	/*
	 * Terminating the parent, and continuing the daemon in the child.
	 * This guarantees that the daemon is not a sessioin leader,
	 * which pervents it from acquiring a controlling terminal. 
	 */
	if ((pid = fork()) < 0) {
		debug("fork() error: %s.", strerror(errno));
		exit(1);
	} else if (pid != 0) /* parent */ {
		exit(0);
	}

	/* Close all open file descriptors. */
	if (rl.rlim_max == RLIM_INFINITY) {
		rl.rlim_max = 1024;
	}
	for (i = 0; i < (int) rl.rlim_max; i++) {
		close(i);
	}

	/*
	 * Attach file desciprots 0, 1 and 2 to /dev/null,so that 
	 * any library routines that try to read from stdin or
	 * write to stdout or stderr will have no effect.
	 */
	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);

	/* Initialize the log file */
	openlog(PROC_NAME, 0, LOG_DAEMON);
	if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
		debug("Unexpected file descriptos %d %d %d", fd0, fd1, fd2);
		exit(1);
	}
}

int main(void)
{
	int	fd_log;
	int sockfd_serv; 
	int sockfd_clnt;
	struct sockaddr_un clnt_addr;
	socklen_t clnt_addr_size;
	thread_param_t *params;
	pthread_t tid;

#ifndef DEBUG
	/* Be daemon first of all */
	daemonize();
#endif

	debug("main start ...");
	pthread_mutex_init(&mutex, NULL);
	pthread_mutex_init(&mutex2, NULL);

	sockfd_serv	= init_unix_sock();
	fd_log		= init_log_file();

	debug("Listening on [%s]", SOCK_NAME); 
	clnt_addr_size = sizeof(clnt_addr);

	while (1) {
		sockfd_clnt = accept(sockfd_serv, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

		/* Count clients */
		pthread_mutex_lock(&mutex2);
		debug("Current connected num: [%d]", ++num_accept);
		pthread_mutex_unlock(&mutex2);

		if (sockfd_clnt < 0) {
			if(errno == EINTR) continue;
			debug("accept() error: %s.", strerror(errno));
			exit(1);
		}

		params = new_param(sockfd_clnt, fd_log);
		pthread_create(&tid, NULL, write_log, (void*) params);
		pthread_detach(tid);
	}
	close(sockfd_serv);
	exit(0);
}

