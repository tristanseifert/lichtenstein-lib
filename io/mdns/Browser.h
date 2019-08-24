//
// Created by Tristan Seifert on 2019-08-24.
//

#ifndef LIBLICHTENSTEIN_IO_MDNS_BROWSER_H
#define LIBLICHTENSTEIN_IO_MDNS_BROWSER_H

#include <memory>
#include <chrono>
#include <vector>

namespace liblichtenstein::mdns {
  class IBrowserService;

  /**
   * Provides an interface to browse for mDNS services.
   */
  class Browser {
    public:
      using ResultsListType = std::vector<std::shared_ptr<IBrowserService>>;

    public:
      virtual ~Browser() = default;

    public:
      static std::unique_ptr<Browser> create(const std::string name);

    public:
      /**
       * Synchronously browses for services; this would be used by a caller from
       * its own worker thread. Browsing continues for at most as long as the
       * timeout value, but may terminate sooner if the implementation has
       * returned all available data.
       *
       * @param timeout How long to browse for
       */
      virtual void browse(std::chrono::seconds timeout) = 0;

      /**
       * Copies references to the result objects to the provided vector.
       *
       * @param outServices Vector to copy references to
       */
      virtual void getResults(ResultsListType &outServices) = 0;

    public:

  };
}


#endif //LIBLICHTENSTEIN_IO_MDNS_BROWSER_H
