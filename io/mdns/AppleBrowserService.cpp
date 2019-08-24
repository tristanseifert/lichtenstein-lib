//
// Created by Tristan Seifert on 2019-08-24.
//
#include "AppleBrowserService.h"

#include <glog/logging.h>

#include <thread>
#include <chrono>
#include <stdexcept>


namespace liblichtenstein::mdns::platform {
  /**
   * Allocates a new browser service
   *
   * @param interface
   * @param name
   * @param type
   * @param domain
   */
  AppleBrowserService::AppleBrowserService(int interface,
                                           const std::string &name,
                                           const std::string &type,
                                           const std::string &domain) : name(
          name), type(type), domain(domain), interface(interface) {
    VLOG(1) << "New service: " << name << "(type " << type << "), domain "
            << domain << " on interface " << interface;
  }

  /**
   * Resolves the service.
   *
   * @param name
   * @param txt
   */
  void AppleBrowserService::resolve(std::chrono::seconds timeout) {
    DNSServiceErrorType err;

    // reset some state
    {
      std::lock_guard lock(this->resolveLock);
      this->resolveDone = false;
    }

    this->port.reset();
    this->target.reset();

    this->txtRecords.clear();

    // create the operation
    err = DNSServiceResolve(&this->svc, 0, this->interface, this->name.c_str(),
                            this->type.c_str(), this->domain.c_str(),
                            &AppleBrowserService::resolveCallback, this);

    if(err != kDNSServiceErr_NoError) {
      std::stringstream error;
      error << "DNSServiceResolve() failed: " << err;

      throw std::runtime_error(error.str());
    }

    // have it run on a background queue
    err = DNSServiceSetDispatchQueue(this->svc, dispatch_get_global_queue(
            QOS_CLASS_BACKGROUND, 0));

    if(err != kDNSServiceErr_NoError) {
      std::stringstream error;
      error << "DNSServiceSetDispatchQueue() failed: " << err;

      throw std::runtime_error(error.str());
    }

    // wait for timeout to complete or for resolution to finish
    std::unique_lock<std::mutex> lk(this->resolveLock);

    if(this->resolveCv.wait_for(lk, timeout, [this] {
      return (this->resolveDone == true);
    })) {

    } else {
      throw std::runtime_error("Resolution timed out");
    }
//    std::this_thread::sleep_until(std::chrono::system_clock::now() + timeout);

    // clean up here
    DNSServiceRefDeallocate(this->svc);
    this->svc = nullptr;
  }

  /**
   * Callback for DNSServiceQueryRecord
   *
   * @param sdRef
   * @param flags
   * @param interfaceIndex
   * @param errorCode
   * @param fullname
   * @param hosttarget
   * @param port
   * @param txtLen
   * @param txtRecord
   * @param context
   */
  void AppleBrowserService::resolveCallback(DNSServiceRef sdRef,
                                            DNSServiceFlags flags,
                                            uint32_t interfaceIndex,
                                            DNSServiceErrorType errorCode,
                                            const char *fullname,
                                            const char *hosttarget,
                                            uint16_t port, uint16_t txtLen,
                                            const unsigned char *txtRecord,
                                            void *context) {
    // get the service
    auto *service = reinterpret_cast<AppleBrowserService *>(context);

    // handle errors
    if(errorCode != kDNSServiceErr_NoError) {
      LOG(ERROR) << "Error resolving service: " << errorCode;

      // TODO: forward this to browse function

      return;
    }

    // do we have txt data?
    if(txtRecord && txtLen > 1) {
      service->processTxtRecord(txtRecord, txtLen);
    }
    // do we have a full name of the device?
//    if(fullname) {
//      service->name = std::string(fullname);
//    }
    // do we have a target host?
    if(hosttarget) {
      service->target = std::string(hosttarget);
    }

    // do we have a port?
    if(port > 0) {
      service->port = ntohs(port);
    }

    // if no more data is coming, terminate resolving
    if((flags & kDNSServiceFlagsMoreComing) != kDNSServiceFlagsMoreComing) {
      service->resolveDone = true;
      service->resolveCv.notify_all();
    }
  }


  /**
   * Processes a TXT record. This contains one or more byte string in the format
   * of key=value, with a preceeding length byte.
   *
   * @param data TXT record buffer
   * @param len TXT record buffer length
   */
  void AppleBrowserService::processTxtRecord(const unsigned char *data,
                                             size_t len) {
    // remove any existing records
    this->txtRecords.clear();

    // read the data string
    size_t i = 0;

    while(i < len) {
      // read length byte
      uint8_t numBytes = static_cast<uint8_t>(data[i++]);

      // try to create a string
      std::string record((char *) &data[i], numBytes);

      // split into key/value by first equals
      std::string key = record.substr(0, record.find("="));
      std::string value = record.substr(record.find("=") + 1);

      this->txtRecords[key] = value;

      // increment the counter
      i += numBytes;
    }
  }
}