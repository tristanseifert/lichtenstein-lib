//
// Created by Tristan Seifert on 2019-08-17.
//

#ifndef LIBLICHTENSTEIN_APPLESERVICE_H
#define LIBLICHTENSTEIN_APPLESERVICE_H

#include "Service.h"

#include <dns_sd.h>

#include <string>
#include <map>

namespace liblichtenstein::mdns {
  /**
   * A concrete implementation of an mDNS service for Apple platforms. This
   * uses the dnssd/mDNSResponder API.
   */
  class AppleService : public Service {
    public:
      AppleService(const std::string &name, unsigned int port);

      ~AppleService() override;

    public:
      void startAdvertising() override;

      void stopAdvertising() override;

    protected:
      void updateTxtRecords() override;

    private:
      // whether the service ref is valid
      bool isServiceValid = false;
      // service we're advertising
      DNSServiceRef service = nullptr;

      // whether we've created a TXT record
      bool isTxtValid = false;
      // TXT record
      DNSRecordRef txtRecord = nullptr;
  };
}


#endif //LIBLICHTENSTEIN_APPLESERVICE_H
