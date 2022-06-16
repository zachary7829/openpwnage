//
//  ViewController.m
//  openpwnage
//
//  Created by Zachary Keffaber on 4/20/22.
//

#import "ViewController.h"
#import <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#import "jailbreak.h"
#include "LGPL/kpmapAndCo.h"
#include <time.h>

#define UNSLID_BASE 0x80001000

#define UIColorFromRGB(rgbValue) [UIColor \
colorWithRed:((float)((rgbValue & 0xFF0000) >> 16))/255.0 \
green:((float)((rgbValue & 0xFF00) >> 8))/255.0 \
blue:((float)(rgbValue & 0xFF))/255.0 alpha:1.0]

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UILabel *openpwnLabel;
@property (weak, nonatomic) IBOutlet UILabel *notSupportedLabel;
@property (weak, nonatomic) IBOutlet UIButton *jbButton;
//@property (weak, nonatomic) IBOutlet UITextView *consoleView;
@property (weak, nonatomic) IBOutlet UIButton *settingsButton;
-(void)openpwnageConsoleLog:(NSString*)textToLog;
@end

@implementation ViewController

@synthesize consoleView;

id param_;

static id static_consoleView = nil;
-(void)viewDidLoad {
    [super viewDidLoad];
    param_ = self;
    [self setNeedsStatusBarAppearanceUpdate];
    // Do any additional setup after loading the view.
    _jbButton.layer.cornerRadius = 5.0;
    consoleView.layer.cornerRadius = 10.0;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSDateFormatter *dateFormatter=[[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"MM-dd"];
    if ([[dateFormatter stringFromDate:[NSDate date]]isEqualToString:@"04-01"]){
        srand(time(0));
        int randjokenameid = (rand() % 17) + 1;
        if (randjokenameid == 1) {
            _openpwnLabel.text = @"mompwnage";
        } else if (randjokenameid == 2) {
            _openpwnLabel.text = @"bozopwnage"; //hydrate#9351
        } else if (randjokenameid == 3) {
            _openpwnLabel.text = @"Manticore"; //Orangera1n#9957 holy shit it's reel
        } else if (randjokenameid == 4) {
            _openpwnLabel.text = @"nJailbreak"; //flower#1116
        } else if (randjokenameid == 5) {
            _openpwnLabel.text = @"Serenajb"; //Billie#0303
        } else if (randjokenameid == 6) {
            _openpwnLabel.text = @"flowerbreak"; //flower#1116
        } else if (randjokenameid == 7) {
            _openpwnLabel.text = @"Stendra"; //Dan(infinity synbol that i can't type)#9999 coolstar trol
        } else if (randjokenameid == 8) {
            _openpwnLabel.text = @"ligmabreak"; //Neptune#6866 hmm i wonder what this is
        } else if (randjokenameid == 9) {
            _openpwnLabel.text = @"MokitoCoreJB"; //Billie#0303 tbh i don't know what this is supposed to reference
        } else if (randjokenameid == 10) {
            _openpwnLabel.text = @"Zer0Tw0Pwn"; //Neptune#6866
        } else if (randjokenameid == 11) {
            _openpwnLabel.text = @"pastcutsJB"; //flower#1116 (no way!!,,)
        } else if (randjokenameid == 12) {
            _openpwnLabel.text = @"BallsInYoJaws"; //Neptune#6866 erhoihgioer stop
        } else if (randjokenameid == 13) {
            _openpwnLabel.text = @"c0met14"; //Neptune#6866 holy shit iOS 14 jailbreak for iOS 8/9 I can't believe this
        } else if (randjokenameid == 14) {
            _openpwnLabel.text = @"CookieMonster"; //WhitetailAni#1287
        } else if (randjokenameid == 15) {
            _openpwnLabel.text = @"im gay"; //so true
        } else if (randjokenameid == 16) {
            _openpwnLabel.text = @"FurryJB";
        } else if (randjokenameid == 17) {
            _openpwnLabel.text = @"Estrogen";
        }
    } else if ([[dateFormatter stringFromDate:[NSDate date]]isEqualToString:@"05-19"]){
        //when the first build of openpwnage was released. you get a ton of names i considered for a jailbreak, and i didn't want to waste them so I'm throwing them here. anyways yeah they're all shit
        srand(time(0));
        int randjokenameid = (rand() % 17) + 1;
        if (randjokenameid == 1) {
            _openpwnLabel.text = @"Bonobo";
        } else if (randjokenameid == 2) {
            _openpwnLabel.text = @"Malaria";
        } else if (randjokenameid == 3) {
            _openpwnLabel.text = @"WinterSn0w"; //coming to a iPod Touch 1 near you!
        } else if (randjokenameid == 4) {
            _openpwnLabel.text = @"FurryJB"; //suck my cock
        } else if (randjokenameid == 5) {
            _openpwnLabel.text = @"BigshotJB"; //pretty cool jailbreak name tbh
        } else if (randjokenameid == 6) {
            _openpwnLabel.text = @"Vader"; //y'know, from like... star wars?
        } else if (randjokenameid == 7) {
            _openpwnLabel.text = @"EasyPwnage"; //the actual name sounds like so much better imo
        } else if (randjokenameid == 8) {
            _openpwnLabel.text = @"p0wdersn0w"; //huh this actually sounds like it could be the name of some old tethered/untethered jailbreak lol
        } else if (randjokenameid == 9) {
            _openpwnLabel.text = @"richman"; //i don't have anything to comment on this one sorry
        } else if (randjokenameid == 10) {
            _openpwnLabel.text = @"evil_jellyfish"; //used to really like this name, now, tbh sounds stupid
        } else if (randjokenameid == 11) {
            _openpwnLabel.text = @"Pepper"; //if i ever make a iOS 11 untether i'll call it Pepper. but I won't because who tf uses iOS 11 and it's not like i have any devices for it anyway
        } else if (randjokenameid == 12) {
            _openpwnLabel.text = @"milkman"; // MAN
        } else if (randjokenameid == 13) {
            _openpwnLabel.text = @"meguh4x"; // MEGUMIN
        } else if (randjokenameid == 14) {
            _openpwnLabel.text = @"Cherry"; // i don't even like cherries tbh not sure why i loved this name for so long
        } else if (randjokenameid == 15) {
            _openpwnLabel.text = @"newsc00by"; // maybe i got this name from listening to the what's new scooby doo theme some a million times as a kid. i don't remember anything from that show but that theme song slapped hard and still slaps hard now
        } else if (randjokenameid == 16) {
            _openpwnLabel.text = @"sn0wra1n"; // like WinterSn0w but less cool
        } else if (randjokenameid == 17) {
            _openpwnLabel.text = @"PonyJB"; // i am a brony
        }
    }
    _settingsButton.hidden = 1;
    
    consoleView.text = [NSString stringWithFormat:@"[*]openpwnage running on %@ with iOS %@\n", [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding], [[UIDevice currentDevice] systemVersion]];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateHighlighted];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateSelected];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateDisabled];
    
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
        
    olog("Kernel Version: %s\n",newkernv);
    
    olog("openpwnage stage: Beta\n");
    olog("openpwnage build 7\n");
    
    //olog("olog functional!");
    
    //remember to detect free space to check that the bootstrap can be installed
    
    NSArray *supportedDevices = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPad3,4",@"iPad3,5",@"iPad3,6",@"iPhone4,1",@"iPhone5,1",@"iPhone5,2",@"iPhone5,3",@"iPhone5,4",@"iPod5,1", nil];
    //supports all 32bit devices on 9.0-9.3.6 (the kinfo leak works on 8.0-8.4.1 but the mach_ports_register() bug (CVE-2016-4669) doesn't), aka iPad 2, iPad Mini 1, iPad 3, iPad 4, iPhone 4S, iPhone 5, iPhone 5C, iPod Touch 5
    if([supportedDevices containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]){
        NSString *kver = [NSString stringWithCString:newkernv encoding:NSUTF8StringEncoding];
        NSArray *supportedKernVers = [NSArray arrayWithObjects:@"3789.70.16~4",@"3248.61.1~1",@"3248.60.9~1",@"3248.60.8~1",@"3248.60.4~1",@"3248.60.3~3",@"3248.50.21~4",@"3248.50.20~1",@"3248.50.18~1",@"3248.41.4~2",@"3248.41.4~3",@"3248.41.3~1",@"3248.40.173.0.1~1",@"3248.40.166.0.1~1",@"3248.40.155.1.1~3",@"3248.31.3~2",@"3248.21.2~1",@"3248.21.1~2",@"3248.20.39~8",@"3248.20.33.0.1~7",@"3248.10.42~4",@"3248.10.41~1",@"3248.10.38~3",@"3248.10.27~1",@"3248.1.3~1",@"3248.1.2~3",@"3247.1.88.1.1~1",@"3247.1.56~1",@"3247.1.36.0.1~9",@"3247.1.6.1.1~2",@"3216.0.0.1.15~2",@"2784.40.6~1", nil];
        if (!([supportedKernVers containsObject:kver])) {
            [self openpwnageConsoleLog:@"[*]your device is supported by openpwnage, but your iOS version is not\n"];
            [self openpwnageConsoleLog:@"[*]openpwnage supports 32bit 9.0b1-9.3.6 only at the moment\n"];
            _jbButton.hidden = 1;
            consoleView.backgroundColor = UIColorFromRGB(0xF9c9c9);
        } else {
            _notSupportedLabel.hidden = 1;
            if ([@"3789.70.16~4" isEqualToString:kver]) {
                olog("openpwnage support on 10.3.3b6/10.3.3 is not complete\n");
            }
            if ([@"2784.40.6~1" isEqualToString:kver]) {
                olog("openpwnage support on 8.4.1 is not complete\n");
            }
        }
    } else {
        [self openpwnageConsoleLog:@"[*]your device is not supported by openpwnage\n"];
        _jbButton.hidden = 1;
        consoleView.backgroundColor = UIColorFromRGB(0xF9c9c9);
    }
}
- (IBAction)jailbreakButtonPressed:(id)sender {
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateNormal];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateHighlighted];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateSelected];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateDisabled];
    _jbButton.enabled = NO;
    [_jbButton setNeedsDisplay];
    NSLog(@"button pressed");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self performSelector:@selector(openpwnage) withObject:self];
    });
}
    
-(void)openpwnage {
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
        
    olog("Kernel Version: %s\n",newkernv);
    NSString *kver = [NSString stringWithCString:newkernv encoding:NSUTF8StringEncoding];
    if ([@"3789.70.16~4" isEqualToString:kver]) { //iOS 10
        /*[self openpwnageConsoleLog:@"[*]starting jailbreak...\n"];
        task_t tfp0 = sock_port_tfp0();
        [self openpwnageConsoleLog:@"[*]we tried getting tfp0, and holy shit it actually worked\n"];
        [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]tfp0=0x%x\n", tfp0]];
        [self openpwnageConsoleLog:@"[*]we should try getting kbase now, hold on...\n"];
        uintptr_t kernel_base = get_kernel_base(tfp0);
        [self openpwnageConsoleLog:@"[*]ayo, yet another success!\n"];
        [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]huzzah, kbase=0x%08lx\n", kernel_base]];
        [self openpwnageConsoleLog:@"[*]one more thing we need to get before patching: kaslr slide.\n"];
        uintptr_t kaslr_slide = kernel_base - UNSLID_BASE;
        [self openpwnageConsoleLog:@"[*]WOOO! Now we talkin'!\n"];
        [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]slide=0x%08lx\n", kaslr_slide]];
        [self openpwnageConsoleLog:@"[*]obtaining root...\n"];
        if (rootify(tfp0, kernel_base, kaslr_slide)) {
            [self openpwnageConsoleLog:@"[*]we root baby\n"];
        }
        if (is_pmap_patch_success(tfp0, kernel_base, kaslr_slide)) {
            olog("pmap patch success!\n");
        } else {
            olog("pmap patch no success :(\n");
        }*/
    } else if ([@"2784.40.6~1" isEqualToString:kver]) { //iOS 8.4.1
        /*olog("starting jb\n");
        //[self openpwnageConsoleLog:@"[*]aw yeah da hot sauce\n"];
        //consoleView.text = [[NSString alloc]initWithString:[consoleView.text stringByAppendingString:@"fill me with cum already\n"]];
        mach_port_t tfp0 = dajb();
        olog("getting kbase again rather than using our existing one because idfk...\n");
        uint32_t kernel_base = leak_kernel_base();
        olog("[*]woo kbase got... again\n");
        olog("[*]kbase=0x%08lx\n", kernel_base); //this works
        CGRect frame = consoleView.frame;
        frame.size.height -= 1;
        consoleView.frame = frame;
        [consoleView setNeedsDisplay];
        sleep(10);
        olog("[*]calculating kaslr slide...\n");
        uint32_t kaslr_slide = kernel_base - UNSLID_BASE;
        [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]slide=0x%08x\n", kaslr_slide]];
        [self openpwnageConsoleLog:@"[*]obtaining root...\n"];
        if (rootify(tfp0, kernel_base, kaslr_slide)) {
            [self openpwnageConsoleLog:@"[*]we root baby\n"];
            if (is_pmap_patch_success(tfp0, kernel_base, kaslr_slide)) {
                olog("pmap patch success!\n");
            } else {
                olog("pmap patch no success :(\n");
            }
            olog("time for unsandbox...\n");
            unsandbox8(tfp0,kernel_base,kaslr_slide);
        } else {
            [self openpwnageConsoleLog:@"[*]root failed :(\n"];
        }*/
    } else { //iOS 9
    [self openpwnageConsoleLog:@"[*]starting jailbreak...\n"];
    task_t tfp0 = get_kernel_task();
    [self openpwnageConsoleLog:@"[*]we tried getting tfp0, and holy shit it actually worked\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]tfp0=0x%x\n", tfp0]];
    [self openpwnageConsoleLog:@"[*]we should try getting kbase now, hold on...\n"];
    uintptr_t kernel_base = kbase();
    [self openpwnageConsoleLog:@"[*]ayo, yet another success!\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]huzzah, kbase=0x%08lx\n", kernel_base]];
    [self openpwnageConsoleLog:@"[*]one more thing we need to get before patching: kaslr slide.\n"];
    uintptr_t kaslr_slide = kernel_base - UNSLID_BASE;
    [self openpwnageConsoleLog:@"[*]WOOO! Now we talkin'!\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]slide=0x%08lx\n", kaslr_slide]];
    [self openpwnageConsoleLog:@"[*]cleaning up exploit...\n"];
    exploit_cleanup(tfp0);
    [self openpwnageConsoleLog:@"[*]nice and tidy\n"];
    [self openpwnageConsoleLog:@"[*]this is great and all, but now time for actual shit\n"];
    //patch kernel pmap
    [self openpwnageConsoleLog:@"[*]obtaining root...\n"];
    if (rootify(tfp0, kernel_base, kaslr_slide)) {
        [self openpwnageConsoleLog:@"[*]we root baby\n"];
        [self openpwnageConsoleLog:@"[*]now, time to nuke sandbox\n"];
        if (unsandbox(tfp0, kernel_base, kaslr_slide)) {
            [self openpwnageConsoleLog:@"[*]no need to worry about sandbox anymore\n"];
            [self openpwnageConsoleLog:@"[*]attempting remounting...\n"];
            if (remount()) {
                olog("remount success!");
            }
        } else {
            [self openpwnageConsoleLog:@"[*]failed to nuke sandbox\n"];
        }
    } else {
        [self openpwnageConsoleLog:@"[*]failed to get root :(\n"];
    }
    //unpatch pmap
    [self openpwnageConsoleLog:@"[*]that's all for know. more soon (hopefully)\n"];
    //go();
    }
}

-(void)openpwnageConsoleLog: (NSString*)textToLog {
    NSLog(@"%@", [[NSString alloc]initWithString:textToLog]);
    NSMutableString *mutableLog = [consoleView.text mutableCopy];
    consoleView.text = [[NSString alloc]initWithString:[mutableLog stringByAppendingString:textToLog]];
}

void openpwnageCLog(NSString* textToLog) { //terrible method
    [param_ openpwnageConsoleLog:textToLog];
}

@end
