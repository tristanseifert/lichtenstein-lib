//
// Created by Tristan Seifert on 2019-08-24.
//
#include "Browser.h"

#include <glog/logging.h>

#if __APPLE__

#include "AppleBrowser.h"

#endif


namespace liblichtenstein::mdns {
  /**
   * Creates the platform-specific service browser instance.
   *
   * @param name Name of the service to browse for
   * @return A service browser, or nullptr
   */
  std::unique_ptr<Browser> Browser::create(const std::string name) {
#if __APPLE__
    return std::make_unique<platform::AppleBrowser>(name);
#endif

    LOG(ERROR) << "Attempted to create browser for '" << name
               << " but this platform has no mDNS support";
    return nullptr;
  }
}