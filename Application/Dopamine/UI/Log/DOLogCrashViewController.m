//
//  DOLogCrashViewController.m
//  Dopamine
//
//  Created by tomt000 on 14/02/2024.
//

#import "DOLogCrashViewController.h"
#import "DOPSListController.h"
#import "DOPSListItemsController.h"
#import "DOActionMenuButton.h"
#import "DOGlobalAppearance.h"
#import "DOEnvironmentManager.h"
#import "DOUIManager.h"

@interface DOLogCrashViewController ()

@property (nonatomic, copy) NSString *failureMessage;
@property (nonatomic) BOOL rebootRequired;
@property (nonatomic) BOOL recoveryAcknowledged;

@end

@implementation DOLogCrashViewController

- (id)initWithTitle:(NSString*)title
{
    return [self initWithTitle:title rebootRequired:NO];
}

- (id)initWithTitle:(NSString*)title rebootRequired:(BOOL)rebootRequired
{
    if (self = [super init])
    {
        self.failureMessage = title;
        self.rebootRequired = rebootRequired;
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    [DOPSListController setupViewControllerStyle:self];

    NSString *headerTitle = self.rebootRequired ? @"Reboot Required" : DOLocalizedString(@"Log_Error");
    UIView *header = [DOPSListItemsController makeHeader:headerTitle withTarget:self];
    header.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:header];

    [NSLayoutConstraint activateConstraints:@[
        [header.topAnchor constraintEqualToAnchor:self.view.topAnchor constant:5],
        [header.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [header.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [header.heightAnchor constraintEqualToConstant:70]
    ]];
    
    UILabel *failureLabel = [[UILabel alloc] init];
    failureLabel.translatesAutoresizingMaskIntoConstraints = NO;
    failureLabel.numberOfLines = self.rebootRequired ? 0 : 3;
    failureLabel.textAlignment = NSTextAlignmentCenter;
    failureLabel.font = [UIFont systemFontOfSize:13];
    failureLabel.textColor = [UIColor colorWithWhite:1.0 alpha:0.75];
    if (self.rebootRequired) {
        failureLabel.text = [NSString stringWithFormat:@"%@\n\nA full device reboot is required before Dopamine can be opened again. Share the log before rebooting if you need support.", self.failureMessage ?: @"Jailbreak activation did not complete."];
    }
    else {
        failureLabel.text = self.failureMessage;
    }
    [self.view addSubview:failureLabel];

    [NSLayoutConstraint activateConstraints:@[
        [failureLabel.topAnchor constraintEqualToAnchor:header.bottomAnchor constant:2],
        [failureLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:20],
        [failureLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-20]
    ]];

    __block DOActionMenuButton *shareButton;
    UIAction *shareAction = [UIAction actionWithTitle:DOLocalizedString(@"Button_Share") image:[UIImage systemImageNamed:@"square.and.arrow.up" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"share" handler:^(__kindof UIAction * _Nonnull action) {
        [[DOUIManager sharedInstance] shareLogRecordFromView:shareButton];
    }];
    shareButton = [DOActionMenuButton buttonWithAction:shareAction chevron:NO];
    
    shareButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:shareButton];

    UIView *logBottomView = shareButton;
    if (self.rebootRequired) {
        DOActionMenuButton *rebootButton = [DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:DOLocalizedString(@"Button_Reboot") image:[UIImage systemImageNamed:@"power" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"full-device-reboot" handler:^(__kindof UIAction * _Nonnull action) {
            // This path is reboot3 from the already elevated app. It does not
            // spawn jbctl, reboot, or any other BaseBin helper through the
            // systemhook loader that may have just failed. A successful call
            // never returns; if it does fail, keep the recovery screen locked.
            [[DOEnvironmentManager sharedManager] reboot];
        }] chevron:NO];
        rebootButton.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:rebootButton];

        [NSLayoutConstraint activateConstraints:@[
            [shareButton.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:30],
            [shareButton.trailingAnchor constraintEqualToAnchor:self.view.centerXAnchor constant:-6],
            [shareButton.heightAnchor constraintEqualToConstant:30],
            [shareButton.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor constant:-30],
            [rebootButton.leadingAnchor constraintEqualToAnchor:self.view.centerXAnchor constant:6],
            [rebootButton.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-30],
            [rebootButton.heightAnchor constraintEqualToAnchor:shareButton.heightAnchor],
            [rebootButton.bottomAnchor constraintEqualToAnchor:shareButton.bottomAnchor]
        ]];
    }
    else {
        [NSLayoutConstraint activateConstraints:@[
            [shareButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
            [shareButton.heightAnchor constraintEqualToConstant:30],
            [shareButton.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor constant:-30]
        ]];
    }
    
    if (@available(iOS 16.0, *)) {
        _logView = [UITextView textViewUsingTextLayoutManager:false];
    }
    else {
        _logView = [[UITextView alloc] init];
    }
    _logView.translatesAutoresizingMaskIntoConstraints = NO;

    [self.view addSubview:_logView];

    [NSLayoutConstraint activateConstraints:@[
        [_logView.topAnchor constraintEqualToAnchor:failureLabel.bottomAnchor constant:8],
        [_logView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:20],
        [_logView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-20],
        [_logView.bottomAnchor constraintEqualToAnchor:logBottomView.topAnchor constant:-10]
    ]];

    NSArray *reverseLog = [[[DOUIManager sharedInstance] logRecord] reverseObjectEnumerator].allObjects;
    _logView.text = [reverseLog componentsJoinedByString:@"\n"];
    _logView.editable = NO;
    _logView.font = [UIFont systemFontOfSize:14];
    _logView.textColor = [UIColor whiteColor];
    _logView.backgroundColor = [UIColor clearColor];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    if (self.rebootRequired) {
        self.navigationItem.hidesBackButton = YES;
        self.navigationController.interactivePopGestureRecognizer.enabled = NO;
    }
}

- (void)viewWillDisappear:(BOOL)animated
{
    [super viewWillDisappear:animated];
    if (self.rebootRequired && !self.recoveryAcknowledged) {
        return;
    }
    [[UIApplication sharedApplication] performSelector:@selector(suspend)];
    [NSThread sleepForTimeInterval:0.3];
    exit(0);
}

- (void)dismiss
{
    if (self.rebootRequired && !self.recoveryAcknowledged) {
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Reboot Required" message:@"Dopamine cannot be safely reopened until this device has completed a full reboot. You may share the log first." preferredStyle:UIAlertControllerStyleAlert];
        [alertController addAction:[UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:nil]];
        [alertController addAction:[UIAlertAction actionWithTitle:@"I Understand" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
            self.recoveryAcknowledged = YES;
            [self.navigationController popViewControllerAnimated:YES];
        }]];
        [self presentViewController:alertController animated:YES completion:nil];
        return;
    }
    [self.navigationController popViewControllerAnimated:YES];
}


@end
