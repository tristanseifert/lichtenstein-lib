//
// Created by Tristan Seifert on 2019-08-24.
//

#ifndef LIBLICHTENSTEIN_IO_MDNS_APPLEBROWSERSERVICE_H
#define LIBLICHTENSTEIN_IO_MDNS_APPLEBROWSERSERVICE_H

#include "IBrowserService.h"

#include <chrono>
#include <optional>

#include <dns_sd.h>
#include <condition_variable>


namespace liblichtenstein::mdns::platform {
  class AppleBrowser;

  /**
   * Provides the IBrowserService interface to resolve services that were
   * returned during a previous discovery session.
   */
  class AppleBrowserService : public IBrowserService {
      friend class AppleBrowser;

    public:
      AppleBrowserService() = delete;

      ~AppleBrowserService();

    private:
      AppleBrowserService(int interface, const std::string &name,
                          const std::string &type, const std::string &domain);

    public:
      /**
       * Attempts to resolve this service.
       *
       * @param timeout How long to wait to resolve
       * @param name Resultant full DNS name of service
       * @param txt Contents of the primary TXT record of the domain
       */
      void resolve(std::chrono::seconds timeout) override;

      /**
       * Gets the service name, which can be displayed to the user.
       *
       * @return Service name
       */
      [[nodiscard]] std::string getServiceName() const override {
        return this->name;
      }

      /**
       * Gets the service type (such as "_ftp._tcp,anon" discovered with the
       * service.
       *
       * @return Service type
       */
      [[nodiscard]] std::string getServiceType() const override {
        return this->type;
      }

      /**
       * Gets the domain this service was discovered on.
       *
       * @return Domain, if available
       */
      [[nodiscard]] std::optional<std::string> getDomain() const override {
        return this->domain;
      }

      /**
       * Returns the port this service runs on.
       *
       * @return Port number, if available
       */
      [[nodiscard]] std::optional<int> getPort() const override {
        return this->port;
      }

      /**
       * Gets the hostname of the service.
       *
       * @return Domain, if available
       */
      [[nodiscard]] std::optional<std::string> getHostname() const override {
        return this->target;
      }

      /**
       * Gets all TXT records for this service.
       *
       * @param outRecords Vecctor to add the records to
       */
      void getTxtRecords(TxtRecordsType &outRecords) override;

      /**
       * Gets the interface on which the service was discovered.
       *
       * @return Interface on which this service was discovered on, if available
       */
      [[nodiscard]] std::optional<std::string>
      getInterfaceName() const override {
        return this->interfaceName;
      }

    private:
      void processTxtRecord(const unsigned char *data, size_t len);

    private:
      static void resolveCallback(DNSServiceRef sdRef, DNSServiceFlags flags,
                                  uint32_t interfaceIndex,
                                  DNSServiceErrorType errorCode,
                                  const char *fullname, const char *hosttarget,
                                  uint16_t port, uint16_t txtLen,
                                  const unsigned char *txtRecord,
                                  void *context);

    private:
      // are we being deallocated?
      std::atomic_bool shutdown = false;

      // service name
      std::string name;
      // service type
      std::string type;
      // domain on which the service was discovered
      std::string domain;
      // hostname of the machine providing this service
      std::optional<std::string> target;
      // port on which the service runs
      std::optional<int> port;
      // interface name of the interface on which we discovered this
      std::optional<std::string> interfaceName;

      // interface index on which the service was discovered
      int interface;

      // service ref
      DNSServiceRef svc = nullptr;

      // whether the resolution process is done
      std::atomic_bool resolveDone = false;
      // used to wake up the resolve function
      std::condition_variable resolveCv;
      // lock used to protect access to the condition
      std::mutex resolveLock;

      // error during resolving
      DNSServiceErrorType resolveError;

      // lock for TXT records
      std::mutex txtLock;
      // storage for TXT records
      TxtRecordsType txtRecords;
  };
}


#endif //LIBLICHTENSTEIN_IO_MDNS_APPLEBROWSERSERVICE_H
