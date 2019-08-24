//
// Created by Tristan Seifert on 2019-08-24.
//
#include "AppleBrowser.h"
#include "AppleBrowserService.h"

#include <glog/logging.h>

#include <chrono>
#include <thread>
#include <sstream>
#include <stdexcept>


namespace liblichtenstein::mdns::platform {
  /**
   * Creates the service browser.
   */
  AppleBrowser::AppleBrowser(const std::string name) : serviceName(name) {
    DNSServiceErrorType err;

    // create a connection
//    err = DNSServiceCreateConnection(&this->svc);
//
//    if(err != kDNSServiceErr_NoError) {
//      std::stringstream error;
//      error << "DNSServiceCreateConnection() failed: " << err;
//
//      throw std::runtime_error(error.str());
//    }

  }

  /**
   * Deallocates the service ref if it hasn't been already.
   */
  AppleBrowser::~AppleBrowser() {
    if(this->svc) {
      DNSServiceRefDeallocate(this->svc);
      this->svc = nullptr;
    }
  }

  /**
   * Starts browsing for the service.
   *
   * @param timeout Maximum time to browse for services for
   */
  void AppleBrowser::browse(std::chrono::seconds timeout) {
    DNSServiceErrorType err;

    // reset some state
    {
      std::lock_guard lock(this->browseLock);
      this->browseDone = false;
    }

    // set up the browsing
    err = DNSServiceBrowse(&this->svc, 0, 0, this->serviceName.c_str(), nullptr,
                           &AppleBrowser::browseCallback, this);

    if(err != kDNSServiceErr_NoError) {
      std::stringstream error;
      error << "DNSServiceBrowse() failed: " << err;

      throw std::runtime_error(error.str());
    }

    // have it run on a background queue
    err = DNSServiceSetDispatchQueue(this->svc, dispatch_get_global_queue(
            QOS_CLASS_BACKGROUND, 0));

    if(err != kDNSServiceErr_NoError) {
      std::stringstream error;
      error << "DNSServiceSetDispatchQueue() failed: " << err;

      throw std::runtime_error(error.str());
    }

    VLOG(1) << "Set up browse connection: " << this->svc;

    // wait for browsing to be done or time out
    std::unique_lock<std::mutex> lk(this->browseLock);

    if(this->browseCv.wait_for(lk, timeout, [this] {
      return (this->browseDone == true);
    })) {
      // found all data
    } else {
      // browsing timed out, we might still have data
    }

    // deallocate service ref
    DNSServiceRefDeallocate(this->svc);
    this->svc = nullptr;
  }

  void AppleBrowser::browseCallback(DNSServiceRef sdRef, DNSServiceFlags flags,
                                    uint32_t interfaceIndex,
                                    DNSServiceErrorType errorCode,
                                    const char *serviceName,
                                    const char *regtype,
                                    const char *replyDomain, void *context) {
    // get the browser
    auto *browser = reinterpret_cast<AppleBrowser *>(context);

    // handle errors
    if(errorCode != kDNSServiceErr_NoError) {
      LOG(ERROR) << "Error resolving service: " << errorCode;

      // TODO: forward this to browse function

      return;
    }

    // adding a new service?
    if(flags & kDNSServiceFlagsAdd) {
      auto *svc = new AppleBrowserService(interfaceIndex,
                                          std::string(serviceName),
                                          std::string(regtype),
                                          std::string(replyDomain));

      std::lock_guard lock(browser->serviceListLock);
      browser->services.emplace_back(svc);
    }

    // if no more data is coming, we can stop resolution
    if((flags & kDNSServiceFlagsMoreComing) != kDNSServiceFlagsMoreComing) {
      browser->browseDone = true;
      browser->browseCv.notify_all();
    }
  }

  /**
   * Copies references to all services to the vector provided by the caller.
   *
   * @param outServices
   */
  void AppleBrowser::getResults(ResultsListType &outServices) {
    // take lock and copy
    std::lock_guard lock(this->serviceListLock);
    outServices.insert(outServices.end(), this->services.begin(),
                       this->services.end());
  }
}