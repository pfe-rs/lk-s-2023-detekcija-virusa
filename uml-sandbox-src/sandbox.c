#define _GNU_SOURCE
#include <unistd.h>
#include <sched.h>
#include <seccomp.h>
#include "library.h"
#include <sys/mount.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <dirent.h>


void seccomp_initialize()
{
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chroot), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(swapon), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(swapoff), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(syslog), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_file_load), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(keyctl), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(request_key), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);
	
	seccomp_load(ctx);
}

// Napravi novo okruzenje za proces - podesi ostale namespace-ove(ne PID) i mount-uj potrebne filesystem-e
void createenv()
{
	seccomp_initialize();
	
	check( unshare(CLONE_FILES | CLONE_FS | CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS | CLONE_SYSVSEM) )
	check( sethostname("sandbox-fedorapc", 16) )
	check( setdomainname("sandbox-fedorapc", 16) )
	
	// Prebacivanje na mount namespace zastitu:
	check( mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) )
	// pivot_root zahteva da new_root bude mountpoint, pa ga mountujemo sam na sebe
	check( mount("rootfs", "rootfs", NULL, MS_BIND | MS_REC, NULL) )
	check( syscall(SYS_pivot_root, "rootfs", "rootfs/mnt") )
	check( chdir("/") )
	check( umount2("/mnt", MNT_DETACH) )
	// Mount-ovanje tmp i proc filesystema
	check( mount("proc", "/proc", "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID, "") )
	check( mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID, "") )
	//check( mount("mqueue", "rootfs/dev/mqueue", "mqueue", MS_NOSUID | MS_NOEXEC | MS_NODEV, "") )
}

int main(int argc, char *argv[], char *envp[])
{
	check( unshare(CLONE_FILES | CLONE_FS | CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWTIME | CLONE_NEWUTS | CLONE_SYSVSEM) )
	
	if (fork() == 0) {
		createenv();
		setuid(30000);
		char *arg[10];
		arg[0] = "linux";
		arg[1] = "umid=TEST";
		arg[2] = "mem=256M";
		arg[3] = "rootfstype=hostfs";
		arg[4] = "rw";
		arg[5] = "hostfs=rootfs,xattrperm";
		arg[6] = "con=null";
		arg[7] = "con0=null,fd:2";
		arg[8] = "con1=fd:0,fd:1";
		arg[9] = NULL;
		char *env[2];
		env[0] = "HOME=/tmp";
		env[1] = NULL;

		execve("/linux", arg, env);
		printerr("Execve failed: %i\n%m\n", errno);
		exit(1);
	}
	setuid(30000);
	int status;
	wait(&status);
	return WEXITSTATUS(status);
}

