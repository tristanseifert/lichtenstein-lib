//
// Created by Tristan Seifert on 2019-08-17.
//
#ifndef LIBLICHTENSTEIN_SERVICE_H
#define LIBLICHTENSTEIN_SERVICE_H

#include <string>
#include <map>
#include <utility>

namespace liblichtenstein::mdns {
  /**
   * Represents a single service, as advertised over mDNS. It provides some
   * convenient helpers for setting name, any additional attributes (via the
   * TXT records) and controlling advertisement.
   *
   * @note This is an abstract base class. You should create a platform-
   * specific concrete instance instead.
   */
  class Service {
    public:
      Service(std::string name, unsigned int port) : serviceName(
              std::move(name)),
                                                     servicePort(
                                                             port) {}

      virtual ~Service() = default;

    public:
      virtual void startAdvertising() = 0;

      virtual void stopAdvertising() = 0;

      virtual void
      setTxtRecord(const std::string &record, const std::string &value) {
        this->txtRecords[record] = value;
        this->updateTxtRecords();
      }

      virtual void removeTxtRecord(const std::string &record) {
        this->txtRecords.erase(record);
        this->updateTxtRecords();
      }

    protected:
      virtual void updateTxtRecords() = 0;

    protected:
      // name of the service to advertise
      std::string serviceName;
      // port on which the service runs
      unsigned int servicePort;

      // all TXT records for this service
      std::map<std::string, std::string> txtRecords;
  };
}

#endif //LIBLICHTENSTEIN_SERVICE_H
