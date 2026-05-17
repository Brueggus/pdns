/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnscrypt.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "dolog.hh"
#include <unistd.h>

BOOST_AUTO_TEST_SUITE(test_dnscrypt_cc)

#ifdef HAVE_DNSCRYPT

static time_t oneDayFromNow(time_t now)
{
  return now + static_cast<time_t>(24 * 60 * 3600);
}

static PacketBuffer makeAnonymizedDNSCryptQuery(const std::array<uint8_t, 16>& target, uint16_t port, const PacketBuffer& payload)
{
  PacketBuffer query{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00};
  query.insert(query.end(), target.begin(), target.end());
  query.push_back(static_cast<uint8_t>(port >> 8U));
  query.push_back(static_cast<uint8_t>(port & 0xffU));
  query.insert(query.end(), payload.begin(), payload.end());
  return query;
}

// plaintext query for cert
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQuery)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.name.");
  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::TXT, QClass::IN, 0);
  packetWriter.getHeader()->rd = 0;

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  query->parsePacket(plainQuery, false, now);

  BOOST_CHECK_EQUAL(query->isValid(), true);
  BOOST_CHECK_EQUAL(query->isEncrypted(), false);

  PacketBuffer response;

  query->getCertificateResponse(now, response);

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  MOADNSParser mdp(false, reinterpret_cast<const char*>(response.data()), response.size());

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "2.name.");
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::TXT);
}

BOOST_AUTO_TEST_CASE(DNSCryptAnonymizedRelayDisabled)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  PacketBuffer payload(sizeof(DNSCryptQueryHeader), 0);
  payload.at(0) = 1;
  const std::array<uint8_t, 16> quad9{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x09, 0x09, 0x09, 0x09}};
  auto query = makeAnonymizedDNSCryptQuery(quad9, 443, payload);
  PacketBuffer response;

  BOOST_CHECK(ctx->handleAnonymizedDNSCryptQuery(query, response) == DNSCryptAnonymizedQueryResult::Drop);
  BOOST_CHECK(response.empty());
}

BOOST_AUTO_TEST_CASE(DNSCryptAnonymizedRelayRejectsPrivateTarget)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptAnonymizedRelayConfig config;
  config.enabled = true;
  ctx->setAnonymizedRelayConfig(config);

  PacketBuffer payload(sizeof(DNSCryptQueryHeader), 0);
  payload.at(0) = 1;
  const std::array<uint8_t, 16> localhost{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01}};
  auto query = makeAnonymizedDNSCryptQuery(localhost, 443, payload);
  PacketBuffer response;

  BOOST_CHECK(ctx->handleAnonymizedDNSCryptQuery(query, response) == DNSCryptAnonymizedQueryResult::SelfAnswered);
  BOOST_CHECK(response.empty());
}

// invalid plaintext query (A)
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQueryInvalidA)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.name.");

  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 0;

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  query->parsePacket(plainQuery, false, now);

  BOOST_CHECK_EQUAL(query->isValid(), false);
}

// invalid plaintext query (wrong provider name)
BOOST_AUTO_TEST_CASE(DNSCryptPlaintextQueryInvalidProviderName)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSName name("2.WRONG.name.");

  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::TXT, QClass::IN, 0);
  packetWriter.getHeader()->rd = 0;

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  query->parsePacket(plainQuery, false, now);

  BOOST_CHECK_EQUAL(query->isValid(), false);
}

// valid encrypted query
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValid)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  DNSCryptPublicKeyType clientPublicKey;
  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  DNSCryptClientNonceType clientNonce{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B};

  DNSName name("www.powerdns.com.");
  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::AAAA, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;

  size_t initialSize = plainQuery.size();
  int res = ctx->encryptQuery(plainQuery, 4096, clientPublicKey, clientPrivateKey, clientNonce, false, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(plainQuery.size() > initialSize);

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);

  query->parsePacket(plainQuery, false, now);

  BOOST_CHECK_EQUAL(query->isValid(), true);
  BOOST_CHECK_EQUAL(query->isEncrypted(), true);

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  MOADNSParser mdp(true, reinterpret_cast<const char*>(plainQuery.data()), plainQuery.size());

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

  BOOST_CHECK_EQUAL(mdp.d_qname, name);
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::AAAA);
}

BOOST_AUTO_TEST_CASE(DNSCryptEncryptedTCPQueryValid)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  DNSCryptPublicKeyType clientPublicKey;
  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  DNSCryptClientNonceType clientNonce{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B};

  DNSName name("www.powerdns.com.");
  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::AAAA, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;

  size_t initialSize = plainQuery.size();
  int res = ctx->encryptQuery(plainQuery, 4096, clientPublicKey, clientPrivateKey, clientNonce, true, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(plainQuery.size() > initialSize);

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);

  query->parsePacket(plainQuery, true, now);

  BOOST_CHECK_EQUAL(query->isValid(), true);
  BOOST_CHECK_EQUAL(query->isEncrypted(), true);

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  MOADNSParser mdp(true, reinterpret_cast<const char*>(plainQuery.data()), plainQuery.size());

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

  BOOST_CHECK_EQUAL(mdp.d_qname, name);
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::AAAA);
}

BOOST_AUTO_TEST_CASE(DNSCryptEncryptResponse)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  DNSCryptPublicKeyType clientPublicKey;
  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  DNSCryptClientNonceType clientNonce{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B};

  DNSName name("www.powerdns.com.");
  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::AAAA, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;

  plainQuery.resize(4096U);
  int res = ctx->encryptQuery(plainQuery, 8192, clientPublicKey, clientPrivateKey, clientNonce, false, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, 0);

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);

  query->parsePacket(plainQuery, false, now);

  BOOST_CHECK_EQUAL(query->isValid(), true);
  BOOST_CHECK_EQUAL(query->isEncrypted(), true);

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> responseWriter(response, name, QType::AAAA, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  response.resize(4049U);

  query->encryptResponse(response, 4096U, false);
}

BOOST_AUTO_TEST_CASE(DNSCryptEncryptResponsePadding)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  DNSCryptPublicKeyType clientPublicKey;
  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  DNSCryptClientNonceType clientNonce{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B};

  DNSName name("www.powerdns.com.");
  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::AAAA, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;

  int res = ctx->encryptQuery(plainQuery, 4096, clientPublicKey, clientPrivateKey, clientNonce, false, std::make_shared<DNSCryptCert>(resolverCert));
  BOOST_REQUIRE_EQUAL(res, 0);

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);
  query->parsePacket(plainQuery, false, now);

  BOOST_REQUIRE_EQUAL(query->isValid(), true);
  BOOST_REQUIRE_EQUAL(query->isEncrypted(), true);

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> responseWriter(response, name, QType::AAAA, QClass::IN, 0);
  responseWriter.getHeader()->rd = 1;
  PacketBuffer originalResponse = response;

  res = query->encryptResponse(response, 4096U, false);
  BOOST_REQUIRE_EQUAL(res, 0);
  BOOST_REQUIRE_GE(response.size(), sizeof(DNSCryptResponseHeader) + DNSCRYPT_MAC_SIZE);

  const auto* responseNonce = response.data() + DNSCRYPT_RESOLVER_MAGIC_SIZE;
  const auto* encryptedResponse = response.data() + sizeof(DNSCryptResponseHeader);
  const size_t encryptedResponseLen = response.size() - sizeof(DNSCryptResponseHeader);
  PacketBuffer decryptedResponse(encryptedResponseLen - DNSCRYPT_MAC_SIZE);

  res = crypto_box_open_easy(decryptedResponse.data(), encryptedResponse, encryptedResponseLen, responseNonce, resolverCert.signedData.resolverPK.data(), clientPrivateKey.key.data());
  BOOST_REQUIRE_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(decryptedResponse.size() % DNSCRYPT_PADDED_BLOCK_SIZE, 0U);
  BOOST_REQUIRE_GT(decryptedResponse.size(), originalResponse.size());
  BOOST_CHECK_EQUAL(decryptedResponse.at(originalResponse.size()), 0x80U);
  for (size_t pos = originalResponse.size() + 1; pos < decryptedResponse.size(); pos++) {
    BOOST_CHECK_EQUAL(decryptedResponse.at(pos), 0U);
  }
}

// valid encrypted query with not enough room
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValidButShort)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  DNSCryptCertSignedData::ResolverPublicKeyType clientPublicKey;

  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  DNSCryptClientNonceType clientNonce{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B};

  DNSName name("www.powerdns.com.");
  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::AAAA, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;

  int res = ctx->encryptQuery(plainQuery, /* not enough room */ plainQuery.size(), clientPublicKey, clientPrivateKey, clientNonce, false, std::make_shared<DNSCryptCert>(resolverCert));
  BOOST_CHECK_EQUAL(res, ENOBUFS);
}

// valid encrypted query with old key
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryValidWithOldKey)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  DNSCryptCertSignedData::ResolverPublicKeyType clientPublicKey;

  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  DNSCryptClientNonceType clientNonce{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B};

  DNSName name("www.powerdns.com.");
  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::AAAA, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;

  size_t initialSize = plainQuery.size();
  int res = ctx->encryptQuery(plainQuery, 4096, clientPublicKey, clientPrivateKey, clientNonce, false, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(plainQuery.size() > initialSize);

  DNSCryptCert newResolverCert;
  DNSCryptContext::generateCertificate(2, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, newResolverCert);
  ctx->addNewCertificate(newResolverCert, resolverPrivateKey);
  ctx->markInactive(resolverCert.getSerial());

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);

  query->parsePacket(plainQuery, false, now);

  BOOST_CHECK_EQUAL(query->isValid(), true);
  BOOST_CHECK_EQUAL(query->isEncrypted(), true);

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
  MOADNSParser mdp(true, reinterpret_cast<const char*>(plainQuery.data()), plainQuery.size());

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

  BOOST_CHECK_EQUAL(mdp.d_qname, name);
  BOOST_CHECK(mdp.d_qclass == QClass::IN);
  BOOST_CHECK(mdp.d_qtype == QType::AAAA);
}

// valid encrypted query with wrong key
BOOST_AUTO_TEST_CASE(DNSCryptEncryptedQueryInvalidWithWrongKey)
{
  DNSCryptPrivateKey resolverPrivateKey;
  DNSCryptCert resolverCert;
  DNSCryptCertSignedData::ResolverPublicKeyType providerPublicKey;
  DNSCryptCertSignedData::ResolverPrivateKeyType providerPrivateKey;
  time_t now = time(nullptr);
  DNSCryptContext::generateProviderKeys(providerPublicKey, providerPrivateKey);
  DNSCryptContext::generateCertificate(1, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, resolverCert);
  auto ctx = std::make_shared<DNSCryptContext>("2.name", resolverCert, resolverPrivateKey);

  DNSCryptPrivateKey clientPrivateKey;
  DNSCryptCertSignedData::ResolverPublicKeyType clientPublicKey;

  DNSCryptContext::generateResolverKeyPair(clientPrivateKey, clientPublicKey);

  DNSCryptClientNonceType clientNonce{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B};

  DNSName name("www.powerdns.com.");
  PacketBuffer plainQuery;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(plainQuery, name, QType::AAAA, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;

  size_t initialSize = plainQuery.size();
  int res = ctx->encryptQuery(plainQuery, 4096, clientPublicKey, clientPrivateKey, clientNonce, false, std::make_shared<DNSCryptCert>(resolverCert));

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK(plainQuery.size() > initialSize);

  DNSCryptCert newResolverCert;
  DNSCryptContext::generateCertificate(2, now, oneDayFromNow(now), DNSCryptExchangeVersion::VERSION1, providerPrivateKey, resolverPrivateKey, newResolverCert);
  ctx->addNewCertificate(newResolverCert, resolverPrivateKey);
  ctx->markInactive(resolverCert.getSerial());
  ctx->removeInactiveCertificate(resolverCert.getSerial());

  /* we have removed the old certificate, we can't decrypt this query */

  std::shared_ptr<DNSCryptQuery> query = std::make_shared<DNSCryptQuery>(ctx);

  query->parsePacket(plainQuery, false, now);

  BOOST_CHECK_EQUAL(query->isValid(), false);
}

#endif

BOOST_AUTO_TEST_SUITE_END();
