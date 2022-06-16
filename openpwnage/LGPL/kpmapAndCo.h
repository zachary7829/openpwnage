//
//  kpmapAndCo.h
//  openpwnage
//
//  Created by Zachary Keffaber on 6/15/22.
//

#ifndef kpmapAndCo_h
#define kpmapAndCo_h

void patch_kernel_pmap(tfp0, kernel_base);
void pmap_unpatch(task_t tfp0);
bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
bool rootify(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
void run_cmd(char *cmd, ...);

#endif /* kpmapAndCo_h */
