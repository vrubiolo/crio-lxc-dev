#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h> 
#include <sched.h> // setns
#include <errno.h>

#include <lxc/lxccontainer.h>

#include <sys/syscall.h>

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

// requires kernel >= 5.3
static int
pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
       unsigned int flags)
{
   return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}


// crio-lxc-kill implements race-free signal processing for LXC containers using the kernel pidfd API.
// This implementation requires a kernel version >= 5.8 
// See https://lwn.net/Articles/801319/ for details about the kernel pidfd API.
void main(int argc, char** argv)
{
	int ret;
	struct lxc_container *c;
	int err = EXIT_FAILURE;
	const char * lxcpath;
	const char * name;
	int signum = 15;
	int pidfd = -1;

	if (argc != 4) {
		fprintf(stderr, "invalid cmdline: usage %s <lxcpath> <container_name> <signum>\n", argv[0]);
		exit(err);
	}
	lxcpath = argv[1];
	name = argv[2];
	signum = atoi(argv[3]);
	
	c = lxc_container_new(name, lxcpath);
	if (!c) {
		fprintf(stderr, "failed to create lxc_container\n");
		goto out;
	}

	if (!c->is_running(c)) {
		fprintf(stderr, "container is not running\n");
		goto out;
	}

	// pidfd must be a non-negative integer, see 'man 2 pidfd_open'
	pidfd = c->init_pidfd(c);
	if (pidfd < 0) {
		fprintf(stderr, "Invalid init pidfd value %d\n", pidfd);
		goto out;
	}

	// Entering the PID namespace of the container is required for pidfd_send_signalto work. 
	// Using the pidfd with setns requires a kernel >= 5.8
	if (setns(pidfd, CLONE_NEWPID) != 0) {
		fprintf(stderr, "setns failed with error %s\n", strerror(errno));
		err = errno;
		goto out;
	}

	if (pidfd_send_signal(pidfd, signum, NULL, 0) != 0 ){
		fprintf(stderr, "failed so send signal num %d to container pidfd: %s\n", signum, strerror(errno));
		err = errno;
		goto out;
	}

	err = EXIT_SUCCESS;

out:
	if (pidfd >= 0) {
 	 close(pidfd);	
	}
	lxc_container_put(c);
	exit(err);
}
