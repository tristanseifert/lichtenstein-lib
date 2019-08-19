//
// Created by Tristan Seifert on 2019-08-19.
//
#include "Service.h"

#if __APPLE__

#include "AppleService.h"

#else
#warning "mDNS is not supported on this platform"
#endif

#include <glog/logging.h>


namespace liblichtenstein::mdns {
  /**
   * Creates a new service, appropriate for this platform.
   *
   * @param name Service name
   * @param port Service port
   *
   * @return Allocated service or nullptr
   */
  std::unique_ptr<Service> Service::create(std::string name,
                                           unsigned int port) {
#if __APPLE__
    return std::make_unique<platform::AppleService>(name, port);
#endif

    LOG(ERROR) << "Attempted to create service '" << name << "' on port "
               << port << " but this platform has no mDNS support";
    return nullptr;
  }
}