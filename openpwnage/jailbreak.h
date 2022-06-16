//
//  jailbreak.h
//  openpwnage
//
//  Created by Zachary Keffaber on 4/24/22.
//

#ifndef jailbreak_h
#define jailbreak_h

//bool rootify(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
bool unsandbox(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
bool unsandbox8(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
//void patch_kernel_pmap(void);
//bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
void olog(char *format, ...);
//void pmap_unpatch(task_t tfp0);
bool remount(void);
uint32_t find_kernel_pmap(uintptr_t kernel_base);
uint32_t kread_uint32(uint32_t addr, task_t tfp0);
void kwrite_uint32(uint32_t addr, uint32_t value, task_t tfp0);
NSString *KernelVersion(void);
uint32_t hardcoded_allproc(void);
#endif /* jailbreak_h */
