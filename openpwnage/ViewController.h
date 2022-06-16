//
//  ViewController.h
//  openpwnage
//
//  Created by Zachary Keffaber on 4/20/22.
//

#import <UIKit/UIKit.h>
#include <mach/mach.h>
#include <sys/utsname.h>

@interface ViewController : UIViewController
@property (nonatomic, retain) IBOutlet UITextView *consoleView;
void openpwnageCLog(NSString* textToLog);
uintptr_t kbase(void);
task_t get_kernel_task(void);
void exploit_cleanup(task_t);
@end
