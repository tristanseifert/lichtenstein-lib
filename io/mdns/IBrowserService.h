//
// Created by Tristan Seifert on 2019-08-24.
//

#ifndef LIBLICHTENSTEIN_IO_MDNS_IBROWSERSERVICE_H
#define LIBLICHTENSTEIN_IO_MDNS_IBROWSERSERVICE_H

#include <string>
#include <unordered_map>
#include <optional>
#include <chrono>

namespace liblichtenstein::mdns {
  /**
   * Defines a platform-specific object representing a service, as discovered by
   * the browser's platform implementation.
   */
  class IBrowserService {
    public:
      using TxtRecordsType = std::unordered_map<std::string, std::string>;

    public:
      virtual ~IBrowserService() = default;

    public:
      /**
       * Attempts to resolve this service.
       *
       * @param timeout How long to wait for service to be resolved
       */
      virtual void resolve(std::chrono::seconds timeout) = 0;


      /**
       * Gets the service name, which can be displayed to the user.
       *
       * @return Service name
       */
      [[nodiscard]] virtual std::string getServiceName() const = 0;

      /**
       * Gets the service type (such as "_ftp._tcp,anon" discovered with the
       * service.
       *
       * @return Service type
       */
      [[nodiscard]] virtual std::string getServiceType() const = 0;

      /**
       * Gets the domain this service was discovered on.
       *
       * @return Domain, if available
       */
      [[nodiscard]] virtual std::optional<std::string> getDomain() const = 0;

      /**
       * Returns the port this service runs on.
       *
       * @return Port number, if available
       */
      [[nodiscard]] virtual std::optional<int> getPort() const = 0;

      /**
       * Gets the hostname of the service.
       *
       * @return Domain, if available
       */
      [[nodiscard]] virtual std::optional<std::string> getHostname() const = 0;
  };
}

#endif //LIBLICHTENSTEIN_IO_MDNS_IBROWSERSERVICE_H
