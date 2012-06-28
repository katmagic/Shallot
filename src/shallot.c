/* program: shallot (based on the popular onionhash program by Bebop)
 * version: 0.0.2
 * purpose: brute-force customized SHA1-hashes of RSA keys for Tor's
 *          .onion namespace
 * license: OSI-approved MIT License
 * credits: Bebop, for onionhash, which credits the following:
 *          - Plasmoid         (The Hacker's Choice)
 *          - Roger Dingledine (Tor Project)
 *          - Nick Mathewson   (Tor Project)
 *          - Eric Young       (OpenSSL Project)
 *
 *          I would also like to thank the following testers/benchmarkers:
 *          - seeess         (Linux)
 *          - Cheeze-        (Linux, OS X)
 *          - Tas            (Linux, OS X, OpenBSD)
 *          - ^wAc^          (FreeBSD)
 *          - cybernetseraph (OpenBSD)
 *
 *          Special thanks to nickm for some debugging assistance!
 *          Extra-special thanks to Tas for his patience and assistance
 *            in getting shallot to build on OpenBSD, OS X, and Linux
 *
 * contact: mention bugs to <`Orum@OFTC or `Orum@ORC>
 */

/* TODO:
 * - finish all TODOs
 * - allow -m to be used with -f (use file for status output) [v0.0.3]
 */

#include "config.h"

#include "math.h"
#include "error.h"
#include "print.h"
#include "thread.h"
#include "defines.h"
#include "globals.h"

#ifdef LINUX_PORT
// Linux specific headers
#include "linux.h"
#include <fcntl.h>
#include <string.h> // included with something else on *BSD
#include <sys/uio.h>
#endif

#ifdef BSD
// BSD specific headers
#include <sys/param.h> // needed on OpenBSD
#include <sys/sysctl.h>
#endif

#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

void terminate(int signum) { // Ctrl-C/kill handler
  error(X_SGNL_INT_TERM);
}

int main(int argc, char *argv[]) { // onions are fun, here we go
  signal(SIGTERM, terminate); // always let people kill

  if(argc < 2) // not enough arguments
    usage();

  // set up our initial values
  uint8_t daemon = 0, optimum = 0;
  uint32_t threads = 1, x = 1;
  char *file = 0;
  elim = DEFAULT_E_LIMIT;
  loop = 0;
  found = 0;
  monitor = 0;

  #ifdef BSD                                   // my
  int mib[2] = { CTL_HW, HW_NCPU };            // how
  size_t size = sizeof(threads);               // easy
  if(sysctl(mib, 2, &threads, &size, NULL, 0)) // BSD
    error(X_SYSCTL_FAILED);                    // is

  #elif defined(LINUX_PORT) // Oh no!  We're on Linux... :(
  // ...even *Windows 95* (gasp!) has a better way of doing this...
  // TODO: move this to linux.c
  char cpuinfo[CPUINFO_BUF_SIZE] = "";
  int fd = open(CPUINFO_PATH, O_RDONLY);

  if(fd < 0)
    error(X_BAD_FILE_DESC);

  threads--; // reset threads to 0
  size_t r = 0;
  ssize_t tmp = 1; // must not initially be 0!
  uint16_t used = 0;

  do {
    if(tmp)
      tmp = read(fd, &cpuinfo[r], CPUINFO_BUF_SIZE - r); // fill the buffer

    if(tmp < 0) // something went wrong
      error(X_ABNORMAL_READ);

    r += tmp; // add how much we read

    if(r < CPUINFO_BUF_SIZE)
      cpuinfo[r] = 0;

    threads += parse_cpuinfo(&cpuinfo[0], (uint16_t)r, &used);
    r -= used; // subtract what we parsed

    memmove(&cpuinfo[0], &cpuinfo[used], r);
  } while(used > 0);

  close(fd); // TODO: add error handling! (is there any point?)

  if(!threads) { // This is needed for Linux/ARM (do not remove!)
    printf("WARNING: No CPUs detected.  Defaulting to 1 thread... "
           "(or manually specify thread count with -t)\n");
    threads++;
  }

  #elif defined(GENERIC)
  printf("WARNING: Threads will default to 1 unless specified with -t\n");
  #endif

  // pattern help
  if( argc >= x)
  {
    if( strcmp(argv[x], "-p") == 0)
    {
      pattern();
    }
  }

  for(; x < argc - 1; x++) { // options parsing
    if(argv[x][0] != '-') {
      fprintf(stderr, "Error: Options must start with '-'\n");
      usage();
    }
    uint32_t y = 1;
    for(; argv[x][y] != '\0'; y++) {
      uint8_t dbreak = 0;
      switch(argv[x][y]) {
        case 'd': { // daemonize
          daemon = 1;
          break;
        }
        case 'm': { // monitor
          monitor = 1;
          break;
        }
        case 'o': { // prime optimization
          optimum = 1;
          break;
        }
        case 'f': { // file <file>
          if((argv[x][y + 1] != '\0') || (x + 1 > argc)) {
            fprintf(stderr, "Error: -f format is '-f <file>'\n");
            usage();
          }
          file = argv[x + 1];
          dbreak = 1;
          break;
        }
        case 't': { // threads
          if((argv[x][y + 1] != '\0') || (x + 1 > argc)) {
            fprintf(stderr, "Error: -t format is '-t threads'\n");
            usage();
          }
          threads = strtoul(argv[x + 1], NULL, 0);
          dbreak = 1;
          break;
        }
        case 'x': { // maximum execution time
          if((argv[x][y + 1] != '\0') || (x + 1 > argc)) {
            fprintf(stderr, "Error: -x format is '-x <max exec time in seconds>'\n");
            usage();
          }
          maxexectime = strtoul(argv[x + 1], NULL, 0);
          dbreak = 1;
          break;
        }

        case 'e': { // e limit
          if((argv[x][y + 1] != '\0') || (x + 1 > argc)) {
            fprintf(stderr, "Error: -e format is '-e limit'\n");
            usage();
          }
          elim = strtoull(argv[x + 1], NULL, 0);
          dbreak = 1;
          break;
        }
        default: { // unrecognized
          fprintf(stderr, "Error: Unrecognized option - '%c'\n", argv[x][y]);
          usage();
          break; // redundant... but safe :)
        }
      }
      if(dbreak) {
        x++; // skip the next param
        break;
      }
    }
  }

  // now for our sanity checks
  if(threads < 1)
    error(X_INVALID_THRDS);

  if(monitor && file)
    error(X_EXCLUSIVE_OPT);

  if(!(elim & 1) || (elim < RSA_PK_EXPONENT) || (elim > MAXIMUM_E_LIMIT))
    error(X_INVALID_E_LIM);

  if(daemon && !file)
    error(X_NEED_FILE_OUT);

  // compile regular expression from argument
  char *pattern = argv[argc - 1];

  if(*pattern == '-')
    error(X_REGEX_INVALID);

  regex = malloc(REGEX_COMP_LMAX);

  if(regcomp(regex, pattern, REG_EXTENDED | REG_NOSUB))
    error(X_REGEX_COMPILE);

  if(file) {
    umask(077); // remove permissions to be safe

    // redirect output
    if (
			(freopen(file, "w", stdout) == NULL) ||
			(freopen(file, "w", stderr) == NULL)
		) error(X_FILE_OPEN_ERR);
  }

  if(daemon && (getppid() != 1)) { // daemonize if we should
    pid_t pid = fork();

    if(pid < 0) // fork failed
      error(X_DAEMON_FAILED);

    if(pid) // exit on the parent process
      exit(0);

    if(setsid() < 0) // get a new SID
      error(X_DAEMON_FAILED);

    if(chdir("/") < 0) // cd to root
      error(X_DAEMON_FAILED);

		// block input
    if (freopen("/dev/null", "r", stdin) == NULL)
			error(X_FILE_OPEN_ERR);

    // ignore certain signals
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);

  } else signal(SIGINT, terminate); // die on CTRL-C

  pthread_t thrd;

  // create our threads for 2+ cores
  for(x = 1; x < threads; x++) {

    if(pthread_create(&thrd, NULL, worker, &optimum))
      error(X_THREAD_CREATE);
  }

  if(monitor) {
    // TODO: when support is added for -mv, put a message here
    if(pthread_create(&thrd, NULL, monitor_proc, NULL))
      error(X_THREAD_CREATE);
  }

  worker(&optimum); // use main thread for brute-forcing too

  if(pthread_self() != lucky_thread) { // be safe and avoid EDEADLK

    pthread_join(lucky_thread, NULL); // wait for the lucky thread to exit
  }

  regfree(regex);
  return 0;
}
