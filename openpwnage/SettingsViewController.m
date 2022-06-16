//
//  SettingsViewController.m
//  openpwnage
//
//  Created by Zachary Keffaber on 5/26/22.
//

#import "SettingsViewController.h"

@interface SettingsViewController ()

@end

@implementation SettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (IBAction)remountFSSwitch:(id)sender {
    
}
- (IBAction)TweakInjectionSwitch:(id)sender {
    if ([sender isOn]) {
        //NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        //NSString *documentsDirectory = [paths objectAtIndex:0];
        //NSString *filename = [documentsDirectory stringByAppendingPathComponent:@"disabletweakinjection.txt"];
    }
}

@end
