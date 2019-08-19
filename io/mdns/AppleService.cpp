//
// Created by Tristan Seifert on 2019-08-17.
//
#include "AppleService.h"
#include "Service.h"

#include <glog/logging.h>

#include <string>
#include <sstream>

#include <netinet/in.h>
#include <dns_sd.h>


namespace liblichtenstein::mdns::platform {
  /**
   * Initializes an mDNS service advertised via dnssd.
   *
   * @param name Name of the service
   * @param port Port on which the service runs
   */
  AppleService::AppleService(const std::string &name, unsigned int port)
          : Service(name, port) {
    // we don't have to do anything here
  }

  /**
   * Cleans up any resources allocated during the service's lifetime.
   */
  AppleService::~AppleService() {
    // clean up service if needed
    if (this->isServiceValid) {
      this->stopAdvertising();
    }

    // clean up memory
  }


  /**
   * Starts advertising the service. It will be registered with dnssd.
   */
  void AppleService::startAdvertising() {
    DNSServiceErrorType err;

    // abort if service is valid already
    if (this->isServiceValid) return;

    // attempt to create a service
    err = DNSServiceRegister(&this->service, 0, 0, nullptr,
                             this->serviceName.c_str(), nullptr, nullptr,
                             htons(this->servicePort), 0, nullptr, nullptr,
                             this);

    if (err != kDNSServiceErr_NoError) {
      VLOG(1) << "DNSServiceRegister failed: " << err;
    } else {
      this->isServiceValid = true;
    }
  }

  /**
   * Stops advertising the service by freeing it.
   */
  void AppleService::stopAdvertising() {
    if (this->isServiceValid) {
      this->isServiceValid = false;
      DNSServiceRefDeallocate(this->service);
    }
  }


  /**
   * Updates the TXT records on the service.
   */
  void AppleService::updateTxtRecords() {
    DNSServiceErrorType err;

    // check if we need to remove all records
    if (this->txtRecords.empty()) {
      // only do this if the record exists
      if (this->isTxtValid) {
        err = DNSServiceRemoveRecord(this->service, this->txtRecord, 0);

        // handle errors
        if (err != kDNSServiceErr_NoError) {
          LOG(WARNING) << "Failed to remove TXT record: " << err;
        } else {
          this->isTxtValid = false;
        }
      }
    }

    // build one large TXT record string from all records
    std::stringstream recordStream;

    for (auto const&[key, val] : this->txtRecords) {
      std::stringstream subKeyStream;
      subKeyStream << key << '=' << val;

      const auto &subKey = subKeyStream.str();

      recordStream << static_cast<char>(subKey.length());
      recordStream << subKey;
    }

    // get the C string of records
    const std::string recordStr = recordStream.str();

    const size_t recordLen = recordStr.length();
    const char *recordBytes = recordStr.c_str();

    // check whether we need to update or modify the existing record
    if (this->isTxtValid) {
      err = DNSServiceUpdateRecord(this->service, this->txtRecord, 0,
                                   recordLen, recordBytes, 0);

      if (err != kDNSServiceErr_NoError) {
        LOG(WARNING) << "Failed to update TXT record: " << err;
      }
    }
      // we need to create a new record
    else {
      memset(&this->txtRecord, 0, sizeof(this->txtRecord));

      err = DNSServiceAddRecord(this->service, &this->txtRecord, 0,
                                kDNSServiceType_TXT, recordLen, recordBytes,
                                0);


      if (err == kDNSServiceErr_NoError) {
        this->isTxtValid = true;
      } else {
        LOG(WARNING) << "Failed to create TXT record: " << err;
      }
    }
  }
}