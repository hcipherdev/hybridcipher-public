#import <FileProvider/FileProvider.h>
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

static NSString *const HCRootContainerSignalIdentifier =
    @"__hybridcipher_root_container__";

static char *HCFileProviderCopyCString(NSString *message) {
  const char *utf8 = [message UTF8String];
  if (utf8 == NULL) {
    utf8 = "unknown macOS File Provider error";
  }
  return strdup(utf8);
}

static char *HCFileProviderCopyError(NSString *operation, NSError *error) {
  if (error == nil) {
    return NULL;
  }
  NSString *message = [NSString
      stringWithFormat:@"%@ failed: Error Domain=%@ Code=%ld \"%@\" UserInfo=%@",
                       operation, error.domain, (long)error.code,
                       error.localizedDescription, error.userInfo];
  return HCFileProviderCopyCString(message);
}

static char *HCFileProviderCopyTimeout(NSString *operation) {
  NSString *message =
      [NSString stringWithFormat:@"%@ timed out waiting for File Provider",
                                 operation];
  return HCFileProviderCopyCString(message);
}

static char *HCFileProviderFindDomain(NSString *identifierString,
                                      NSFileProviderDomain **domainOut) {
  NSFileProviderDomainIdentifier identifier =
      (NSFileProviderDomainIdentifier)identifierString;

  dispatch_semaphore_t listSemaphore = dispatch_semaphore_create(0);
  __block NSError *listError = nil;
  __block NSFileProviderDomain *matchingDomain = nil;

  [NSFileProviderManager
      getDomainsWithCompletionHandler:^(NSArray<NSFileProviderDomain *> *domains,
                                        NSError *error) {
        if (error != nil) {
          listError = error;
        } else {
          for (NSFileProviderDomain *domain in domains) {
            if ([domain.identifier isEqualToString:identifier]) {
              matchingDomain = domain;
              break;
            }
          }
        }
        dispatch_semaphore_signal(listSemaphore);
      }];

  if (dispatch_semaphore_wait(listSemaphore,
                              dispatch_time(DISPATCH_TIME_NOW,
                                            30 * NSEC_PER_SEC)) != 0) {
    return HCFileProviderCopyTimeout(@"list File Provider domains");
  }
  if (listError != nil) {
    return HCFileProviderCopyError(@"list File Provider domains", listError);
  }
  if (domainOut != NULL) {
    *domainOut = matchingDomain;
  }
  return NULL;
}

char *HCFileProviderRegisterDomain(const char *domain_id,
                                   const char *display_name) {
  @autoreleasepool {
    if (domain_id == NULL || domain_id[0] == '\0') {
      return HCFileProviderCopyCString(@"missing File Provider domain id");
    }

    NSString *identifierString = [NSString stringWithUTF8String:domain_id];
    NSString *displayNameString =
        display_name == NULL || display_name[0] == '\0'
            ? @"HybridCipher"
            : [NSString stringWithUTF8String:display_name];
    NSFileProviderDomainIdentifier identifier =
        (NSFileProviderDomainIdentifier)identifierString;

    dispatch_semaphore_t listSemaphore = dispatch_semaphore_create(0);
    __block NSError *listError = nil;
    __block BOOL alreadyRegistered = NO;

    [NSFileProviderManager
        getDomainsWithCompletionHandler:^(NSArray<NSFileProviderDomain *> *domains,
                                          NSError *error) {
          if (error != nil) {
            listError = error;
          } else {
            for (NSFileProviderDomain *domain in domains) {
              if ([domain.identifier isEqualToString:identifier]) {
                alreadyRegistered = YES;
                break;
              }
            }
          }
          dispatch_semaphore_signal(listSemaphore);
        }];

    if (dispatch_semaphore_wait(listSemaphore,
                                dispatch_time(DISPATCH_TIME_NOW,
                                              30 * NSEC_PER_SEC)) != 0) {
      return HCFileProviderCopyTimeout(@"list File Provider domains");
    }
    if (listError != nil) {
      return HCFileProviderCopyError(@"list File Provider domains", listError);
    }
    if (alreadyRegistered) {
      return NULL;
    }

    NSFileProviderDomain *domain =
        [[NSFileProviderDomain alloc] initWithIdentifier:identifier
                                            displayName:displayNameString];
    dispatch_semaphore_t addSemaphore = dispatch_semaphore_create(0);
    __block NSError *addError = nil;

    [NSFileProviderManager addDomain:domain
                   completionHandler:^(NSError *error) {
                     addError = error;
                     dispatch_semaphore_signal(addSemaphore);
                   }];

    if (dispatch_semaphore_wait(addSemaphore,
                                dispatch_time(DISPATCH_TIME_NOW,
                                              30 * NSEC_PER_SEC)) != 0) {
      return HCFileProviderCopyTimeout(@"register File Provider domain");
    }
    return HCFileProviderCopyError(@"register File Provider domain", addError);
  }
}

char *HCFileProviderUnregisterDomain(const char *domain_id) {
  @autoreleasepool {
    if (domain_id == NULL || domain_id[0] == '\0') {
      return HCFileProviderCopyCString(@"missing File Provider domain id");
    }

    NSString *identifierString = [NSString stringWithUTF8String:domain_id];
    __block NSFileProviderDomain *matchingDomain = nil;
    char *lookupError = HCFileProviderFindDomain(identifierString, &matchingDomain);
    if (lookupError != NULL) {
      return lookupError;
    }
    if (matchingDomain == nil) {
      return NULL;
    }

    dispatch_semaphore_t removeSemaphore = dispatch_semaphore_create(0);
    __block NSError *removeError = nil;
    [NSFileProviderManager removeDomain:matchingDomain
                      completionHandler:^(NSError *error) {
                        removeError = error;
                        dispatch_semaphore_signal(removeSemaphore);
                      }];

    if (dispatch_semaphore_wait(removeSemaphore,
                                dispatch_time(DISPATCH_TIME_NOW,
                                              30 * NSEC_PER_SEC)) != 0) {
      return HCFileProviderCopyTimeout(@"unregister File Provider domain");
    }
    return HCFileProviderCopyError(@"unregister File Provider domain",
                                   removeError);
  }
}

char *HCFileProviderSignalDomain(const char *domain_id,
                                 const char *container_ids) {
  @autoreleasepool {
    if (domain_id == NULL || domain_id[0] == '\0') {
      return HCFileProviderCopyCString(@"missing File Provider domain id");
    }

    NSString *identifierString = [NSString stringWithUTF8String:domain_id];
    __block NSFileProviderDomain *matchingDomain = nil;
    char *lookupError = HCFileProviderFindDomain(identifierString, &matchingDomain);
    if (lookupError != NULL) {
      return lookupError;
    }
    if (matchingDomain == nil) {
      return HCFileProviderCopyCString(@"File Provider domain not found");
    }

    NSFileProviderManager *manager =
        [NSFileProviderManager managerForDomain:matchingDomain];
    if (manager == nil) {
      return HCFileProviderCopyCString(@"File Provider manager unavailable");
    }

    NSMutableArray<NSFileProviderItemIdentifier> *identifiers =
        [NSMutableArray arrayWithObject:
                            NSFileProviderWorkingSetContainerItemIdentifier];
    if (container_ids != NULL && container_ids[0] != '\0') {
      NSString *encodedIdentifiers = [NSString stringWithUTF8String:container_ids];
      for (NSString *identifier in
           [encodedIdentifiers componentsSeparatedByString:@"\n"]) {
        if (identifier.length == 0 ||
            [identifier
                isEqualToString:
                    NSFileProviderWorkingSetContainerItemIdentifier]) {
          continue;
        }
        if ([identifier isEqualToString:HCRootContainerSignalIdentifier]) {
          [identifiers addObject:NSFileProviderRootContainerItemIdentifier];
          continue;
        }
        [identifiers addObject:(NSFileProviderItemIdentifier)identifier];
      }
    }

    for (NSFileProviderItemIdentifier identifier in identifiers) {
      dispatch_semaphore_t signalSemaphore = dispatch_semaphore_create(0);
      __block NSError *signalError = nil;
      [manager signalEnumeratorForContainerItemIdentifier:identifier
                                        completionHandler:^(NSError *error) {
                                          signalError = error;
                                          dispatch_semaphore_signal(
                                              signalSemaphore);
                                        }];

      if (dispatch_semaphore_wait(signalSemaphore,
                                  dispatch_time(DISPATCH_TIME_NOW,
                                                30 * NSEC_PER_SEC)) != 0) {
        return HCFileProviderCopyTimeout(
            @"signal File Provider domain enumerator");
      }
      if (signalError != nil) {
        return HCFileProviderCopyError(
            @"signal File Provider domain enumerator", signalError);
      }
    }

    return NULL;
  }
}

void HCFileProviderFreeCString(char *value) {
  if (value != NULL) {
    free(value);
  }
}
