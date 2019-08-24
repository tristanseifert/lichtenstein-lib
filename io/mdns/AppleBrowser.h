//
// Created by Tristan Seifert on 2019-08-24.
//

#ifndef LIBLICHTENSTEIN_APPLEBROWSER_H
#define LIBLICHTENSTEIN_APPLEBROWSER_H

#include "Browser.h"

#include <string>
#include <chrono>
#include <mutex>

#include <dns_sd.h>


namespace liblichtenstein::mdns::platform {
  class AppleBrowserService;

  /**
   * A pretty thin wrapper around the DNSServiceBrowse-family of calls for mDNS
   * support on macOS.
   */
  class AppleBrowser : public Browser {
    public:
      explicit AppleBrowser(const std::string name);

      ~AppleBrowser();

    public:
      void browse(std::chrono::seconds timeout) override;

      void getResults(ResultsListType &outServices) override;

    private:
      static void browseCallback(DNSServiceRef sdRef, DNSServiceFlags flags,
                                 uint32_t interfaceIndex,
                                 DNSServiceErrorType errorCode,
                                 const char *serviceName, const char *regtype,
                                 const char *replyDomain, void *context);


    private:
      // are we being deallocated?
      std::atomic_bool shutdown = false;

      // service name to browse for
      std::string serviceName;

      // browser service
      DNSServiceRef svc = nullptr;

      // whether the browsing process is done
      std::atomic_bool browseDone = false;
      // used to wake up the browse function
      std::condition_variable browseCv;
      // lock used to protect access to the condition
      std::mutex browseLock;

      // error during browsing
      DNSServiceErrorType browseError;

      // lock protecting access to service list
      std::mutex serviceListLock;
      // service list
      std::vector<std::shared_ptr<AppleBrowserService>> services;
  };
}


#endif //LIBLICHTENSTEIN_APPLEBROWSER_H
