#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h> // dirname
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

int mask_paths_at(int rootfs, int runtime, const char *masked)
{
	// limits.h PATH_MAX
	char line[PATH_MAX];
	const char *rel;
	int fd;
	FILE *f;

	fd = openat(runtime, masked, O_RDONLY);
	if (fd == -1) {
  	if (errno == ENOENT)
      return 0;
		return -1;
  }

	f = fdopen(fd, "r");
	if (f == NULL) {
		close(fd);
		return -1;
	}

	if (fchdir(rootfs) != 0)
		goto out;

	while (fgets(line, sizeof(line), f) != NULL) {
		line[strlen(line) - 1] = '\0';		  // remove newline;
		rel = (line[0] == '/') ? line + 1 : line; // trim leading '/'
		struct stat path_stat;
		if (stat(rel, &path_stat) != 0) {
			if (errno == ENOENT) {
#ifdef DEBUG
      fprintf(stderr, "ignore non existing filepath %s\n", rel);
#endif
        errno = 0;
				continue;
      }
			goto out;
		}

		if (S_ISDIR(path_stat.st_mode)) {
#ifdef DEBUG
      fprintf(stderr, "masking directory %s\n", rel);
#endif
			if (mount("tmpfs", rel, "tmpfs", MS_RDONLY, NULL) != 0)
				goto out;
		} else {
#ifdef DEBUG
      fprintf(stderr, "masking file %s\n", rel);
#endif
			if (mount("/dev/null", rel, NULL, MS_BIND, NULL) != 0)
				goto out;
		}
	}
out:
	fclose(f);
	return (errno == 0) ? 0 : -1;
}

/* reads up to maxlines-1 lines from path into lines */
int create_devices_at(int rootfs, int runtime, const char *devices)
{
	int fd;
	FILE *f = NULL;
	char linebuf[256];

#ifdef DEBUG
	fprintf(stderr, "reading devices from file %s\n", devices);
#endif
	fd = openat(runtime, devices, O_RDONLY);
	if (fd == -1) {
  	if (errno == ENOENT)
      return 0;
		return -1;
  }

	f = fdopen(fd, "r");
	if (f == NULL) {
    perror("f is null");
		close(fd);
		return -1;
	}

	for (int i = 0;; i++) {
		char mode;
		int major, minor;
		unsigned int filemode;
		int uid, gid;
		char *dir = NULL;
		char *dev = NULL;
		char *sep = NULL;
    char *tmp = NULL;
		int ret;

		if (fchdir(rootfs) == -1) {
      perror("failed to fchdir");
			goto out;
    }

		ret = fscanf(f, "%s %c %d %d %o %d:%d\n", &linebuf[0], &mode,
			     &major, &minor, &filemode, &uid, &gid);
		if (ret == EOF)
			goto out;
		
		if (ret != 7) {
			// errno is not set on a matching error
			fprintf(stderr, "invalid format at line %d at token %d\n", i, ret);
			fclose(f);
			return -1;
		}

		dev = (linebuf[0] == '/') ? linebuf + 1 : linebuf;

		struct stat path_stat;
		if (stat(dev, &path_stat) == 0) {
#ifdef DEBUG
      fprintf(stderr, "ignore existing device %s\n", dev);
#endif
      continue;
    }

    int ft;
    switch (mode) {
      case 'b': ft = S_IFBLK; break;
      case 'c': ft = S_IFCHR; break;
      case 'f': ft = S_IFIFO; break;
      default: 
        fprintf(stderr, "%s:%d unsupported device mode '%c'\n", devices, i, mode);
        return -1;
    }
     

		sep = strrchr(dev, '/');
		if (sep != NULL) {
			*sep = '\0';
      tmp = dev;
			dev = sep + 1;
			for ((dir = strtok(tmp, "/")); dir != NULL; dir = strtok(NULL, "/")) {
			  if (mkdir(dir, 0755) == -1) {
         if (errno == EEXIST)
           errno = 0;
         else 
           goto out;
        }
				if (chdir(dir) != 0) {
          perror("failed to chdir");
					goto out;
        }
			}
		}
#ifdef DEBUG
		printf("mknod device(%s) mode(%c) major(%d) minor(%d), filemode(%o), uid(%d), gid(%d)\n",
		       dev, ft | filemode, major, minor, filemode, uid, gid);
#endif
		ret = mknod(dev, ft | filemode, makedev(major, minor));
		if (ret == -1) {
			fprintf(stderr, "%s:%d failed to create %s\n", devices, i, dev);
			goto out;
		}
    ret = chown(dev, uid, gid); 
		if (ret == -1) {
			fprintf(stderr, "%s:%d chown %d:%d %s failed\n", devices, i, uid, gid, dev);
			goto out;
		}
	}
out:
	fclose(f);
	return (errno == 0) ? 0 : -1;
}

int main(int argc, char **argv)
{
	const char *rootfs_mount;
	const char *config_file;
	const char *runtime_path;
	int rootfs;
	int runtime;
	int ret;

	rootfs_mount = getenv("LXC_ROOTFS_MOUNT");
	config_file = getenv("LXC_CONFIG_FILE");

	if (rootfs_mount == NULL) {
    fprintf(stderr, "LXC_ROOTFS_MOUNT environment variable not set\n");
		ret = 1;
		goto out;
	}
	if (config_file == NULL) {
    fprintf(stderr, "LXC_CONFIG_FILE environment variable not set\n");
		ret = 2;
		goto out;
	}

	rootfs = open(rootfs_mount, O_PATH);
	if (rootfs == -1) {
		perror("failed to open rootfs mount");
		ret = 3;
		goto out;
	}

	runtime_path = dirname(strdup(config_file));
	runtime = open(runtime_path, O_PATH);
	if (rootfs == -1) {
		perror("failed to open runtime_path");
		ret = 4;
		goto out;
	}

	if (create_devices_at(rootfs, runtime, "devices.txt") == -1) {
		perror("failed to create devices");
		ret = 5;
		goto out;
	}

	if (mask_paths_at(rootfs, runtime, "masked.txt") == -1) {
		perror("failed to mask paths");
		ret = 6;
		goto out;
	}

out:
	if (rootfs >= 0)
		close(rootfs);

	if (runtime >= 0)
		close(runtime);

	return ret;
}
