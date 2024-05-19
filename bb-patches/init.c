/* vi: set sw=4 ts=4: */
/*
 * Mini init implementation for busybox
 *
 * Copyright (C) 1995, 1996 by Bruce Perens <bruce@pixar.com>.
 * Copyright (C) 1999-2004 by Erik Andersen <andersen@codepoet.org>
 * Adjusted by so many folks, it's impossible to keep track.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 * Trimmed down for MLinux Minimal by ChenPi11.
 */
//config:config INIT
//config:	bool "init (10 kb)"
//config:	default y
//config:	help
//config:	init is the first program run when the system boots.
//config:

//applet:IF_INIT(APPLET(init, BB_DIR_SBIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_INIT) += init.o


#include "libbb.h"
#include "common_bufsiz.h"
#ifdef __linux__
# include <linux/vt.h>
# include <sys/sysinfo.h>
#endif
#include "reboot.h" /* reboot() constants */

#define CONSOLE_NAME_SIZE 32

/* Each type of actions can appear many times. They will be
 * handled in order. RESTART is an exception, only 1st is used.
 */
/* Wait for completion */
#define WAIT        0x02
/* Start these after WAIT and *dont* wait for completion */
#define ONCE        0x04
/* Start these after ONCE are started, restart on exit */
#define RESPAWN     0x08
/* Like RESPAWN, but wait for <Enter> to be pressed on tty */
#define ASKFIRST    0x10
/*
 * Start these before killing all processes in preparation for
 * running RESTART actions or doing low-level halt/reboot/poweroff
 * (initiated by SIGUSR1/SIGTERM/SIGUSR2).
 * Wait for completion before proceeding.
 */
#define SHUTDOWN    0x40
/*
 * exec() on SIGQUIT. SHUTDOWN actions are started and waited for,
 * then all processes are killed, then init exec's 1st RESTART action,
 * replacing itself by it. If no RESTART action specified,
 * SIGQUIT has no effect.
 */
#define RESTART     0x80

/* A linked list of init_actions, to be read from inittab */
struct init_action {
	struct init_action *next;
	pid_t pid;
	uint8_t action_type;
	char terminal[CONSOLE_NAME_SIZE];
	char command[1];
};

struct globals {
	struct init_action *init_action_list;
	const char *log_console;
	sigset_t delayed_sigset;
	struct timespec zero_ts;
} FIX_ALIASING;
#define G (*(struct globals*)bb_common_bufsiz1)
#define INIT_G() do { \
	setup_common_bufsiz(); \
} while (0)

static void message(const char *fmt, ...)
{
	va_list arguments;
	unsigned l;
	char msg[128];

	msg[0] = '\r';
	va_start(arguments, fmt);
	l = 1 + vsnprintf(msg + 1, sizeof(msg) - 2, fmt, arguments);
	if (l > sizeof(msg) - 2)
		l = sizeof(msg) - 2;
	va_end(arguments);

	msg[l++] = '\n';
	msg[l] = '\0';
	full_write(STDERR_FILENO, msg, l);
}

/* Set terminal settings to reasonable defaults.
 * NB: careful, we can be called after vfork! */
static void set_sane_term(void)
{
	struct termios tty;

	if (tcgetattr(STDIN_FILENO, &tty) != 0)
		return;

	/* set control chars */
	tty.c_cc[VINTR] = 3;	/* C-c */
	tty.c_cc[VQUIT] = 28;	/* C-\ */
	tty.c_cc[VERASE] = 127;	/* C-? */
	tty.c_cc[VKILL] = 21;	/* C-u */
	tty.c_cc[VEOF] = 4;	/* C-d */
	tty.c_cc[VSTART] = 17;	/* C-q */
	tty.c_cc[VSTOP] = 19;	/* C-s */
	tty.c_cc[VSUSP] = 26;	/* C-z */

#ifdef __linux__
	/* use line discipline 0 */
	tty.c_line = 0;
#endif

	/* Make it be sane */
/* On systems where the baud rate is stored in a separate field, we can safely disable these. */
#ifndef CBAUD
# define CBAUD 0
# define CBAUDEX 0
#endif
/* Added CRTSCTS to fix Debian bug 528560 */
#ifndef CRTSCTS
# define CRTSCTS 0
#endif
	tty.c_cflag &= CBAUD | CBAUDEX | CSIZE | CSTOPB | PARENB | PARODD | CRTSCTS;
	tty.c_cflag |= CREAD | HUPCL | CLOCAL;

	/* input modes */
	tty.c_iflag = ICRNL | IXON | IXOFF;

	/* output modes */
	tty.c_oflag = OPOST | ONLCR;

	/* local modes */
	tty.c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;

	tcsetattr_stdin_TCSANOW(&tty);
}

/* Open the new terminal device.
 * NB: careful, we can be called after vfork! */
static int open_stdio_to_tty(const char* tty_name)
{
	/* empty tty_name means "use init's tty", else... */
	if (tty_name[0]) {
		int fd;

		close(STDIN_FILENO);
		/* fd can be only < 0 or 0: */
		fd = device_open(tty_name, O_RDWR);
		if (fd) {
			message("can't open %s: " STRERROR_FMT,
				tty_name
				STRERROR_ERRNO
			);
			return 0; /* failure */
		}
		dup2(STDIN_FILENO, STDOUT_FILENO);
		dup2(STDIN_FILENO, STDERR_FILENO);
	}
	set_sane_term();
	return 1; /* success */
}

static void reset_sighandlers_and_unblock_sigs(void)
{
	bb_signals(0
		| (1 << SIGTSTP)
		| (1 << SIGSTOP)
		, SIG_DFL);
	sigprocmask_allsigs(SIG_UNBLOCK);
}

/* Wrapper around exec:
 * Takes string.
 * If chars like '>' detected, execs '[-]/bin/sh -c "exec ......."'.
 * Otherwise splits words on whitespace, deals with leading dash,
 * and uses plain exec().
 * NB: careful, we can be called after vfork!
 */
static void init_exec(const char *command)
{
	/* +8 allows to write VLA sizes below more efficiently: */
	unsigned command_size = strlen(command) + 8;
	/* strlen(command) + strlen("exec ")+1: */
	char buf[command_size];
	/* strlen(command) / 2 + 4: */
	char *cmd[command_size / 2];
	int dash;

	dash = (command[0] == '-' /* maybe? && command[1] == '/' */);
	command += dash;

	/* See if any special /bin/sh requiring characters are present */
	if (strpbrk(command, "~`!$^&*()=|\\{}[];\"'<>?") != NULL) {
		sprintf(buf, "exec %s", command); /* excluding "-" */
		cmd[0] = (char*)(LIBBB_DEFAULT_LOGIN_SHELL + !dash);
		cmd[1] = (char*)"-c";
		cmd[2] = buf;
		cmd[3] = NULL;
		command = LIBBB_DEFAULT_LOGIN_SHELL + 1;
	} else {
		/* Convert command (char*) into cmd (char**, one word per string) */
		char *word, *next;
		int i = 0;
		next = strcpy(buf, command - dash); /* command including "-" */
		command = next + dash;
		while ((word = strsep(&next, " \t")) != NULL) {
			if (*word != '\0') { /* not two spaces/tabs together? */
				cmd[i] = word;
				i++;
			}
		}
		cmd[i] = NULL;
	}
	/* Here command never contains the dash, cmd[0] might */
	BB_EXECVP(command, cmd);
	message("can't run '%s': "STRERROR_FMT, command STRERROR_ERRNO);
	/* returns if execvp fails */
}

/* Used only by run_actions */
static pid_t run(const struct init_action *a)
{
	pid_t pid;

	if (BB_MMU && (a->action_type & ASKFIRST))
		pid = fork();
	else
		pid = vfork();
	if (pid) {
		if (pid < 0)
			message("can't fork");
		return pid; /* Parent or error */
	}

	/* Child */

	/* Reset signal handlers that were set by the parent process */
	reset_sighandlers_and_unblock_sigs();

	/* Create a new session and make ourself the process group leader */
	setsid();

	/* Open the new terminal device */
	if (!open_stdio_to_tty(a->terminal))
		_exit(EXIT_FAILURE);

	/* NB: on NOMMU we can't wait for input in child, so
	 * "askfirst" will work the same as "respawn". */
	if (BB_MMU && (a->action_type & ASKFIRST)) {
		static const char press_enter[] ALIGN1 =
			"\n==== MLinux Minimal v0.3.0 ====\nPlease press Enter to activate this console. ";
		char c;
		/*
		 * Save memory by not exec-ing anything large (like a shell)
		 * before the user wants it. This is critical if swap is not
		 * enabled and the system has low memory. Generally this will
		 * be run on the second virtual console, and the first will
		 * be allowed to start a shell or whatever an init script
		 * specifies.
		 */
		full_write(STDOUT_FILENO, press_enter, sizeof(press_enter) - 1);
		while (safe_read(STDIN_FILENO, &c, 1) == 1 && c != '\n')
			continue;
	}

	/* Log the process name and args */
	message("starting pid %u, tty '%s': '%s'",
			(int)getpid(), a->terminal, a->command);

	/* Now run it.  The new program will take over this PID,
	 * so nothing further in init.c should be run. */
	init_exec(a->command);
	/* We're still here?  Some error happened. */
	_exit(-1);
}

static struct init_action *mark_terminated(pid_t pid)
{
	struct init_action *a;

	if (pid > 0) {
		update_utmp_DEAD_PROCESS(pid);
		for (a = G.init_action_list; a; a = a->next) {
			if (a->pid == pid) {
				a->pid = 0;
				return a;
			}
		}
	}
	return NULL;
}

static void waitfor(pid_t pid)
{
	/* waitfor(run(x)): protect against failed fork inside run() */
	if (pid <= 0)
		return;

	/* Wait for any child (prevent zombies from exiting orphaned processes)
	 * but exit the loop only when specified one has exited. */
	while (1) {
		pid_t wpid = wait(NULL);
		mark_terminated(wpid);
		if (wpid == pid) /* this was the process we waited for */
			break;
		/* The above is not reliable enough: SIGTSTP handler might have
		 * wait'ed it already. Double check, exit if process is gone:
		 */
		if (kill(pid, 0))
			break;
	}
}

/* Run all commands of a particular type */
static void run_actions(int action_type)
{
	struct init_action *a;

	for (a = G.init_action_list; a; a = a->next) {
		if (!(a->action_type & action_type))
			continue;

		if (a->action_type & (WAIT | ONCE | SHUTDOWN)) {
			pid_t pid = run(a);
			if (a->action_type & (WAIT | SHUTDOWN))
				waitfor(pid);
		}
		if (a->action_type & (RESPAWN | ASKFIRST)) {
			/* Only run stuff with pid == 0. If pid != 0,
			 * it is already running
			 */
			if (a->pid == 0)
				a->pid = run(a);
		}
	}
}

static void new_init_action(uint8_t action_type, const char *command, const char *cons)
{
	struct init_action *a, **nextp;

	/* Scenario:
	 * old inittab:
	 * ::shutdown:umount -a -r
	 * ::shutdown:swapoff -a
	 * new inittab:
	 * ::shutdown:swapoff -a
	 * ::shutdown:umount -a -r
	 * On reload, we must ensure entries end up in correct order.
	 * To achieve that, if we find a matching entry, we move it
	 * to the end.
	 */
	nextp = &G.init_action_list;
	while ((a = *nextp) != NULL) {
		/* Don't enter action if it's already in the list.
		 * This prevents losing running RESPAWNs.
		 */
		if (strcmp(a->command, command) == 0
		 && strcmp(a->terminal, cons) == 0
		) {
			/* Remove from list */
			*nextp = a->next;
			/* Find the end of the list */
			while (*nextp != NULL)
				nextp = &(*nextp)->next;
			a->next = NULL;
			goto append;
		}
		nextp = &a->next;
	}

	a = xzalloc(sizeof(*a) + strlen(command));

	/* Append to the end of the list */
 append:
	*nextp = a;
	a->action_type = action_type;
	strcpy(a->command, command);
	safe_strncpy(a->terminal, cons, sizeof(a->terminal));
}

/* NOTE that if CONFIG_FEATURE_USE_INITTAB is NOT defined,
 * then parse_inittab() simply adds in some default
 * actions (i.e., then starts a pair
 * of "askfirst" shells).  If CONFIG_FEATURE_USE_INITTAB
 * _is_ defined, but /etc/inittab is missing, this
 * results in the same set of default behaviors.
 */
static void parse_inittab(void)
{
	/* No inittab file - set up some default behavior */
	/* Askfirst shell on tty1-4 */
	new_init_action(ASKFIRST, bb_default_login_shell, "/dev/ttyS0");
	/* Restart init when a QUIT is received */
	new_init_action(RESTART, "init", "/dev/ttyS0");
	return;
}

static void pause_and_low_level_reboot(unsigned magic) NORETURN;
static void pause_and_low_level_reboot(unsigned magic)
{
	pid_t pid;

	/* Allow time for last message to reach serial console, etc */
	sleep1();

	/* We have to fork here, since the kernel calls do_exit(EXIT_SUCCESS)
	 * in linux/kernel/sys.c, which can cause the machine to panic when
	 * the init process exits... */
	pid = vfork();
	if (pid == 0) { /* child */
		reboot(magic);
		_exit_SUCCESS();
	}
	/* Used to have "while (1) sleep(1)" here.
	 * However, in containers reboot() call is ignored, and with that loop
	 * we would eternally sleep here - not what we want.
	 */
	waitpid(pid, NULL, 0);
	sleep1(); /* paranoia */
	_exit_SUCCESS();
}

static void run_shutdown_and_kill_processes(void)
{
	/* Run everything to be run at "shutdown".  This is done _prior_
	 * to killing everything, in case people wish to use scripts to
	 * shut things down gracefully... */
	run_actions(SHUTDOWN);

	message("The system is going down NOW!");

	/* Send signals to every process _except_ pid 1 */
	kill(-1, SIGTERM);
	message("Sent SIGTERM to all processes");
	sync();
	sleep1();

	kill(-1, SIGKILL);
	message("Sent SIGKILL to all processes");
	sync();
	/*sleep1(); - callers take care about making a pause */
}

/* Signal handling by init:
 *
 * For process with PID==1, on entry kernel sets all signals to SIG_DFL
 * and unmasks all signals. However, for process with PID==1,
 * default action (SIG_DFL) on any signal is to ignore it,
 * even for special signals SIGKILL and SIGCONT.
 * Also, any signal can be caught or blocked.
 * (but SIGSTOP is still handled specially, at least in 2.6.20)
 *
 * We install two kinds of handlers, "immediate" and "delayed".
 *
 * Immediate handlers execute at any time, even while, say, sysinit
 * is running.
 *
 * Delayed handlers just set a flag variable. The variable is checked
 * in the main loop and acted upon.
 *
 * SIGSTOP and SIGTSTP have immediate handlers. They just wait
 * for SIGCONT to happen.
 *
 * halt/poweroff/reboot and restart have delayed handlers.
 *
 * SIGHUP has a delayed handler, because modifying linked list
 * of struct action's from a signal handler while it is manipulated
 * by the program may be disastrous.
 */

/* The SIGPWR/SIGUSR[12]/SIGTERM handler */
static void halt_reboot_pwoff(int sig) NORETURN;
static void halt_reboot_pwoff(int sig)
{
	const char *m;
	unsigned rb;

	/* We may call run() and it unmasks signals,
	 * including the one masked inside this signal handler.
	 * Testcase which would start multiple reboot scripts:
	 *  while true; do reboot; done
	 * Preventing it:
	 */
	reset_sighandlers_and_unblock_sigs();

	run_shutdown_and_kill_processes();

	m = "halt";
	rb = RB_HALT_SYSTEM;
	if (sig == SIGTERM) {
		m = "reboot";
		rb = RB_AUTOBOOT;
	} else if (sig == SIGUSR2) {
		m = "poweroff";
		rb = RB_POWER_OFF;
	}
	message("Requesting system %s", m);
	pause_and_low_level_reboot(rb);
	/* not reached */
}

/* Handler for QUIT - exec "restart" action,
 * else (no such action defined) do nothing */
static void exec_restart_action(void)
{
	struct init_action *a;

	for (a = G.init_action_list; a; a = a->next) {
		if (!(a->action_type & RESTART))
			continue;

		/* Starting from here, we won't return.
		 * Thus don't need to worry about preserving errno
		 * and such.
		 */

		reset_sighandlers_and_unblock_sigs();

		run_shutdown_and_kill_processes();

#ifdef RB_ENABLE_CAD
		/* Allow Ctrl-Alt-Del to reboot the system.
		 * This is how kernel sets it up for init, we follow suit.
		 */
		reboot(RB_ENABLE_CAD); /* misnomer */
#endif

		if (open_stdio_to_tty(a->terminal)) {
			/* Theoretically should be safe.
			 * But in practice, kernel bugs may leave
			 * unkillable processes, and wait() may block forever.
			 * Oh well. Hoping "new" init won't be too surprised
			 * by having children it didn't create.
			 */
			init_exec(a->command);
		}
		/* Open or exec failed */
		pause_and_low_level_reboot(RB_HALT_SYSTEM);
		/* not reached */
	}
}

/* The SIGSTOP/SIGTSTP handler
 * NB: inside it, all signals except SIGCONT are masked
 * via appropriate setup in sigaction().
 */
static void stop_handler(int sig UNUSED_PARAM)
{
	int saved_errno = errno;

	bb_got_signal = 0;
	signal(SIGCONT, record_signo);

	while (1) {
		pid_t wpid;

		if (bb_got_signal == SIGCONT)
			break;
		/* NB: this can accidentally wait() for a process
		 * which we waitfor() elsewhere! waitfor() must have
		 * code which is resilient against this.
		 */
		wpid = wait_any_nohang(NULL);
		mark_terminated(wpid);
		if (wpid <= 0) /* no processes exited? sleep a bit */
			sleep1();
	}

	signal(SIGCONT, SIG_DFL);
	errno = saved_errno;
}

static void check_delayed_sigs(struct timespec *ts)
{
	int sig = sigtimedwait(&G.delayed_sigset, /* siginfo_t */ NULL, ts);
	if (sig <= 0)
		return;

	/* The signal "sig" was caught */

	if (sig == SIGQUIT) {
		exec_restart_action();
		/* returns only if no restart action defined */
	}
	if ((1 << sig) & (0
#ifdef SIGPWR
	    | (1 << SIGPWR)
#endif
	    | (1 << SIGUSR1)
	    | (1 << SIGUSR2)
	    | (1 << SIGTERM)
	)) {
		halt_reboot_pwoff(sig);
	}
}

int init_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int init_main(int argc UNUSED_PARAM, char **argv)
{
	freopen("/dev/ttyS0", "a", stdout); 
	freopen("/dev/ttyS0", "a", stderr);
	freopen("/dev/ttyS0", "r", stdin);
	int stdout_fd = open("/dev/ttyS0", O_WRONLY | O_NONBLOCK | O_NOCTTY);
	if (stdout_fd >= 0) {
		dup2(stdout_fd, STDOUT_FILENO);
		dup2(stdout_fd, STDERR_FILENO);
		xmove_fd(stdout_fd, STDIN_FILENO);
	}

	struct sigaction sa;

	INIT_G();

	/* Some users send poweroff signals to init VERY early.
	 * To handle this, mask signals early.
	 */
	sigaddset(&G.delayed_sigset, SIGINT);  /* Ctrl-Alt-Del */
	sigaddset(&G.delayed_sigset, SIGQUIT); /* re-exec another init */
#ifdef SIGPWR
	sigaddset(&G.delayed_sigset, SIGPWR);  /* halt */
#endif
	sigaddset(&G.delayed_sigset, SIGUSR1); /* halt */
	sigaddset(&G.delayed_sigset, SIGTERM); /* reboot */
	sigaddset(&G.delayed_sigset, SIGUSR2); /* poweroff */
	sigaddset(&G.delayed_sigset, SIGCHLD); /* make sigtimedwait() exit on SIGCHLD */
	sigprocmask(SIG_BLOCK, &G.delayed_sigset, NULL);

	if (argv[1] && strcmp(argv[1], "-q") == 0) {
		return kill(1, SIGHUP);
	}

	/* Figure out where the default console should be */
	putenv((char*)"TERM=linux");
	set_sane_term();
	xchdir("/");
	setsid();

	/* Make sure environs is set to something sane */
	putenv((char *) bb_PATH_root_path);
	putenv((char *) "SHELL=/bin/sh");
	putenv((char *) "USER=root"); /* needed? why? */
	/* Linux kernel sets HOME="/" when execing init,
	 * and it can be overridden (but not unset?) on kernel's command line.
	 * We used to set it to "/" here, but now we do not:
	 */
	//putenv((char *) "HOME=/");

	if (argv[1])
		xsetenv("RUNLEVEL", argv[1]);

	/* Check if we are supposed to be in single user mode */
	if (argv[1]
	 && (strcmp(argv[1], "single") == 0 || strcmp(argv[1], "-s") == 0 || LONE_CHAR(argv[1], '1'))
	) {
		/* ??? shouldn't we set RUNLEVEL="b" here? */
		/* Start a shell on console */
		new_init_action(RESPAWN, bb_default_login_shell, "");
	} else {
		/* Not in single user mode - see what inittab says */
		parse_inittab();
	}

	/* Set up STOP signal handlers */
	/* Stop handler must allow only SIGCONT inside itself */
	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sigdelset(&sa.sa_mask, SIGCONT);
	sa.sa_handler = stop_handler;
	sa.sa_flags = SA_RESTART;
	sigaction_set(SIGTSTP, &sa); /* pause */
	/* Does not work as intended, at least in 2.6.20.
	 * SIGSTOP is simply ignored by init
	 * (NB: behavior might differ under strace):
	 */
	sigaction_set(SIGSTOP, &sa); /* pause */

	/* Now run everything that needs to be run */
	/* First run anything that wants to block */
	run_actions(WAIT);
	check_delayed_sigs(&G.zero_ts);
	/* Next run anything to be run only once */
	run_actions(ONCE);

	/* Now run the looping stuff for the rest of forever */
	while (1) {
		/* (Re)run the respawn/askfirst stuff */
		run_actions(RESPAWN | ASKFIRST);

		/* Wait for any signal (typically it's SIGCHLD) */
		check_delayed_sigs(NULL); /* NULL timespec makes it wait */

		/* Wait for any child process(es) to exit */
		while (1) {
			pid_t wpid;
			struct init_action *a;

			wpid = waitpid(-1, NULL, WNOHANG);
			if (wpid <= 0)
				break;

			a = mark_terminated(wpid);
			if (a) {
				message("process '%s' (pid %u) exited. "
						"Scheduling for restart.",
						a->command, (unsigned)wpid);
			}
		}

		/* Don't consume all CPU time - sleep a bit */
		sleep1();
	} /* while (1) */
}


//usage:#define init_trivial_usage
//usage:       ""
//usage:#define init_full_usage "\n\n"
//usage:       "Init is the first process started during boot. It never exits."
//usage:#define init_notes_usage
//usage:	"This version of init is designed to be run only by the kernel.\n"
//usage:	"\n"
//usage:	"BusyBox init doesn't support multiple runlevels. The runlevels field of\n"
//usage:	"the /etc/inittab file is completely ignored by BusyBox init. If you want\n"
//usage:	"runlevels, use sysvinit.\n"
//usage:	"\n"
//usage:	"BusyBox init works just fine without an inittab. If no inittab is found,\n"
//usage:	"it has the following default behavior:\n"
//usage:	"\n"
//usage:	"	::askfirst:/bin/sh\n"
//usage:	"	::shutdown:/sbin/swapoff -a\n"
//usage:	"	::shutdown:/bin/umount -a -r\n"
//usage:	"	::restart:/sbin/init\n"
//usage:	"	tty2::askfirst:/bin/sh\n"
//usage:	"	tty3::askfirst:/bin/sh\n"
//usage:	"	tty4::askfirst:/bin/sh\n"
//usage:	"\n"
//usage:	"		WARNING: This field has a non-traditional meaning for BusyBox init!\n"
//usage:	"		The id field is used by BusyBox init to specify the controlling tty for\n"
//usage:	"		the specified process to run on. The contents of this field are\n"
//usage:	"		appended to \"/dev/\" and used as-is. There is no need for this field to\n"
//usage:	"		be unique, although if it isn't you may have strange results. If this\n"
//usage:	"		field is left blank, then the init's stdin/out will be used.\n"
//usage:	"\n"
//usage:	"	<runlevels>:\n"
//usage:	"\n"
//usage:	"		The runlevels field is completely ignored.\n"
//usage:	"\n"
//usage:	"	<action>:\n"
//usage:	"\n"
//usage:	"		Valid actions include: sysinit, respawn, askfirst, wait,\n"
//usage:	"		once, restart, and shutdown.\n"
//usage:	"\n"
//usage:	"		The available actions can be classified into two groups: actions\n"
//usage:	"		that are run only once, and actions that are re-run when the specified\n"
//usage:	"		process exits.\n"
//usage:	"\n"
//usage:	"		Run only-once actions:\n"
//usage:	"\n"
//usage:	"		Run repeatedly actions:\n"
//usage:	"\n"
//usage:	"			'respawn' actions are run after the 'once' actions. When a process\n"
//usage:	"			started with a 'respawn' action exits, init automatically restarts\n"
//usage:	"			it. Unlike sysvinit, BusyBox init does not stop processes from\n"
//usage:	"			respawning out of control. The 'askfirst' actions acts just like\n"
//usage:	"			respawn, except that before running the specified process it\n"
//usage:	"			displays the line \"Please press Enter to activate this console.\"\n"
//usage:	"			and then waits for the user to press enter before starting the\n"
//usage:	"			specified process.\n"
//usage:	"\n"
//usage:	"		Unrecognized actions (like initdefault) will cause init to emit an\n"
//usage:	"		error message, and then go along with its business. All actions are\n"
//usage:	"		run in the order they appear in /etc/inittab.\n"
//usage:	"\n"
//usage:	"	<process>:\n"
//usage:	"\n"
//usage:	"		Specifies the process to be executed and its command line.\n"
//usage:	"\n"
//usage:	"Example /etc/inittab file:\n"
//usage:	"\n"
//usage:	"	# This is run first except when booting in single-user mode\n"
//usage:	"	#\n"
//usage:	"	::sysinit:/etc/init.d/rcS\n"
//usage:	"	\n"
//usage:	"	# /bin/sh invocations on selected ttys\n"
//usage:	"	#\n"
//usage:	"	# Start an \"askfirst\" shell on the console (whatever that may be)\n"
//usage:	"	::askfirst:-/bin/sh\n"
//usage:	"	# Start an \"askfirst\" shell on /dev/tty2-4\n"
//usage:	"	tty2::askfirst:-/bin/sh\n"
//usage:	"	tty3::askfirst:-/bin/sh\n"
//usage:	"	tty4::askfirst:-/bin/sh\n"
//usage:	"	\n"
//usage:	"	# /sbin/getty invocations for selected ttys\n"
//usage:	"	#\n"
//usage:	"	tty4::respawn:/sbin/getty 38400 tty4\n"
//usage:	"	tty5::respawn:/sbin/getty 38400 tty5\n"
//usage:	"	\n"
//usage:	"	\n"
//usage:	"	# Example of how to put a getty on a serial line (for a terminal)\n"
//usage:	"	#\n"
//usage:	"	#::respawn:/sbin/getty -L ttyS0 9600 vt100\n"
//usage:	"	#::respawn:/sbin/getty -L ttyS1 9600 vt100\n"
//usage:	"	#\n"
//usage:	"	# Example how to put a getty on a modem line\n"
//usage:	"	#::respawn:/sbin/getty 57600 ttyS2\n"
//usage:	"	\n"
//usage:	"	# Stuff to do when restarting the init process\n"
//usage:	"	::restart:/sbin/init\n"
//usage:	"	\n"
//usage:	"	# Stuff to do before rebooting\n"
//usage:	"	::shutdown:/bin/umount -a -r\n"
//usage:	"	::shutdown:/sbin/swapoff -a\n"
