//
// Created by Tristan Seifert on 2019-08-24.
//
#include "../io/mdns/Browser.h"
#include "../io/mdns/IBrowserService.h"

#include <glog/logging.h>

#include <iostream>
#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>

using namespace std::chrono_literals;

using Browser = liblichtenstein::mdns::Browser;

/**
 * Browses for all services of the type specified on the command line.
 *
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char **argv) {
  // initialize logging
  FLAGS_stderrthreshold = 0;
  FLAGS_logtostderr = true;
  FLAGS_v = 2;
  google::InitGoogleLogging(argv[0]);

  // get arguments
  if(argc != 2) {
    std::cerr << "usage: " << argv[0] << " service" << std::endl;
    return -1;
  }

  const std::string service = std::string(argv[1]);

  // create browser and wait 5s for some results
  LOG(INFO) << "Searching for service '" << service << "'";

  auto browser = Browser::create(service);
  browser->browse(2s);

  // get results
  Browser::ResultsListType results;
  browser->getResults(results);

  LOG(INFO) << "Got " << results.size() << " results";

  // print them
  std::stringstream str;

  str << "Found clients:" << std::endl;

  str << std::setw(16) << "Service Type";
  str << std::setw(10) << "Interface";
  str << std::setw(20) << "Name";
  str << std::setw(32) << "Host";
  str << std::setw(6) << "Port";
  str << " TXT Record";
  str << std::endl;

  for(auto &svc : results) {
    liblichtenstein::mdns::IBrowserService::TxtRecordsType txt;

    // resolve record
    svc->resolve(1s);

    // convert txt records to string
    svc->getTxtRecords(txt);

    std::stringstream txtStr;

    for(auto &[key, value] : txt) {
      txtStr << key << "=" << value << " ";
    }

    // output it
    str << std::setw(16) << svc->getServiceType();
    str << std::setw(10) << (svc->getInterfaceName().has_value()
                             ? svc->getInterfaceName().value() : "N/A");
    str << std::setw(20) << svc->getServiceName();
    str << std::setw(32)
        << (svc->getHostname().has_value() ? svc->getHostname().value()
                                           : "N/A");
    str << std::setw(6)
        << (svc->getPort().has_value() ? std::to_string(svc->getPort().value())
                                       : "N/A");
    str << " " << txtStr.str();
    str << std::endl;
  }

  LOG(INFO) << str.str();
}