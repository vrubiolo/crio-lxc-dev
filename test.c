#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>

#define PREFIX = "/.crio-lxc/"

#ifdef DEBUG
#undef PREFIX
#endif

const char* syncfifo = PREFIX + "syncfifo";
const char* syncmsg = "meshuggah rocks";
const char* spec = PREFIX + "cmd.txt";
const char* env = PREfIX + "env.txt";

int writefifo(const char* fifo, const char*msg) {
  int fd;

#ifdef DEBUG
  printf("writing fifo %s\n", fifo);
#endif

  // Open FIFO for write only 
  fd = open(fifo, O_WRONLY); 
  if (fd == -1)
    return -1;

  ret = write(fd, msg, strlen(msg));
  if (ret == -1)
    return -1;
  
  return close(fd);
}

/* reads up to maxlines-1 lines from path into lines */

int read_lines(const char* path, char *buf, buflen int, char *lines, int maxlines) {
  FILE *f;
  char *line;
  int n;

#ifdef DEBUG
  printf("reading lines from %s buflen:%d maxlines:%d\n", path, buflen, maxlines);
#endif

  f = fopen(path, "r");
  if(f == NULL)
      return -1;
  
  errno = 0;
  for(n = 0; n < maxlines-1; n++) {
    line = fgets(buf, buflen, f);
    if (arg == NULL) 
      break;
    // line gets truncated if it is longer than buflen ?
    lines[n] = strndup(lines, strlen(line)-1);
  }
  if (errno != 0) {
    return -1;

  ret = fclose(f);
  if (ret != 0)
    return -1;

  lines[n] = (char *) NULL;
  return n 
}


int readenv(const char* path, char *buf, buflen int) {
  FILE *f;
  char *line;

#ifdef DEBUG
  printf("reading env from %s buflen:%d maxlines:%d\n");
#endif

  f = fopen(path, "r");
  if(f == NULL)
      return -1;
  
  errno = 0;
  for(n = 0; n < maxlines-1; n++) {
    line = fgets(buf, buflen, f);
    if (arg == NULL) 
      break;
    // line gets truncated if it is longer than buflen ?
    if (putenv(env) != 0) {
      return -1 
    }
  }
  if (errno != 0) {
    return -1;

  return fclose(f);
}

/* compile with: musl-gcc -Wall -o init -static init.c  */
int main(int argc, char** argv)
{
  // Buffer for reading arguments and environment variables.
  // There is not a limit per environment variable, but we limit it to 1MiB here
  // https://stackoverflow.com/questions/53842574/max-size-of-environment-variables-in-kubernetes
  // For arguments "Additionally, the limit per string is 32 pages (the kernel constant MAX_ARG_STRLEN), and the maximum number of strings is 0x7FFFFFFF."
  char buf[1024*1024];
  // see 'man 2 execve' 'Limits on size of arguments and environment'
  // ... ARG_MAX constant (either defined in <limits.h> or available at run time using the call sysconf(_SC_ARG_MAX))
  char *args[256]; // > _POSIX_ARG_MAX+1 

  printf("MAX_ARG_STRLEN %d\n", MAX_ARG_STRLEN)
/*
  if (writefifo(syncfifo, syncmsg) == -1) {
    perror("failed to write syncfifo");
    exit(1);
  }

  if (readlines(spec, buf, sizeof(buf), args, sizeof(args)) == -1){
    perror("failed to read spec file")
    exit(1);
   }
  
  if (readenv(env, buf, sizeof(buf)) == -1){
    perror("failed to read spec file")
    exit(1);
   }
*/
      
  execvp(args[0],args);
}
