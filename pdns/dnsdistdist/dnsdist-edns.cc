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
#include "dnsdist-ecs.hh"
#include "dnsdist-edns.hh"
#include "ednsoptions.hh"
#include "ednspadding.hh"
#include "ednsextendederror.hh"

namespace dnsdist::edns
{
std::pair<std::optional<uint16_t>, std::optional<std::string>> getExtendedDNSError(const PacketBuffer& packet)
{
  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(packet, &optStart, &optLen, &last);

  if (res != 0) {
    return {std::nullopt, std::nullopt};
  }

  size_t optContentStart = 0;
  uint16_t optContentLen = 0;
  uint16_t infoCode{0};
  std::optional<std::string> extraText{std::nullopt};
  /* we need at least 2 bytes after the option length (info-code) */
  if (!isEDNSOptionInOpt(packet, optStart, optLen, EDNSOptionCode::EXTENDEDERROR, &optContentStart, &optContentLen) || optContentLen < sizeof(infoCode)) {
    return {std::nullopt, std::nullopt};
  }
  memcpy(&infoCode, &packet.at(optContentStart), sizeof(infoCode));
  infoCode = ntohs(infoCode);

  if (optContentLen > sizeof(infoCode)) {
    extraText = std::string();
    extraText->resize(optContentLen - sizeof(infoCode));
    memcpy(extraText->data(), &packet.at(optContentStart + sizeof(infoCode)), optContentLen - sizeof(infoCode));
  }
  return {infoCode, std::move(extraText)};
}

bool addExtendedDNSError(PacketBuffer& packet, size_t maximumPacketSize, const SetExtendedDNSErrorOperation& setErrorOp)
{
  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(packet, &optStart, &optLen, &last);

  if (res != 0) {
    /* no EDNS OPT record in the response, something is not right */
    return false;
  }

  EDNSExtendedError ede{.infoCode = setErrorOp.error.infoCode, .extraText = setErrorOp.error.extraText};
  auto edeOptionPayload = makeEDNSExtendedErrorOptString(ede);
  std::string edeOption;
  generateEDNSOption(EDNSOptionCode::EXTENDEDERROR, edeOptionPayload, edeOption);

  PacketBuffer newContent;
  bool ednsAdded = false;
  bool edeAdded = false;
  if (!slowRewriteEDNSOptionInQueryWithRecords(packet, newContent, ednsAdded, EDNSOptionCode::EXTENDEDERROR, edeAdded, setErrorOp.clearExisting, !setErrorOp.clearExisting, edeOption)) {
    return false;
  }

  if (newContent.size() > maximumPacketSize) {
    return false;
  }

  packet = std::move(newContent);
  return true;
}

bool hasEDNSTCPKeepAlive(const PacketBuffer& packet)
{
  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  if (locateEDNSOptRR(packet, &optStart, &optLen, &last) != 0) {
    return false;
  }

  size_t optContentStart = 0;
  uint16_t optContentLen = 0;
  return isEDNSOptionInOpt(packet, optStart, optLen, EDNSOptionCode::TCPKEEPALIVE, &optContentStart, &optContentLen) && optContentLen == 0;
}

bool addEDNSTCPKeepAlive(PacketBuffer& packet, size_t maximumPacketSize, uint16_t timeout)
{
  uint16_t networkTimeout = htons(timeout);
  std::string optionPayload(reinterpret_cast<const char*>(&networkTimeout), sizeof(networkTimeout));

  bool ednsAdded = false;
  bool optionAdded = false;
  return setEDNSOption(packet, EDNSOptionCode::TCPKEEPALIVE, optionPayload, maximumPacketSize, ednsAdded, optionAdded);
}

bool addEDNSPadding(PacketBuffer& packet, size_t maximumPacketSize)
{
  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(packet, &optStart, &optLen, &last);

  if (res != 0) {
    /* no EDNS OPT record in the response, something is not right */
    return false;
  }

  if (isEDNSOptionInOpt(packet, optStart, optLen, EDNSOptionCode::PADDING)) {
    /* padding is already present, exit */
    return false;
  }

  if (packet.size() + 4 > maximumPacketSize) {
    /* Can not pad, as we can't add the PADDING EDNS Option */
    return false;
  }

  size_t remaining = maximumPacketSize - (packet.size() + 4);

  const size_t blockSize = 468;
  size_t modulo = (packet.size() + 4) % blockSize;
  size_t padSize = 0;
  if (modulo > 0) {
    padSize = std::min(blockSize - modulo, remaining);
  }

  std::string paddingPayload = makeEDNSPaddingOptString(padSize);
  std::string padding;
  generateEDNSOption(EDNSOptionCode::PADDING, paddingPayload, padding);

  /* we might have one record after the OPT one, we need to rewrite
     the whole packet because of compression */
  PacketBuffer newContent;
  bool ednsAdded = false;
  bool edeAdded = false;
  if (!slowRewriteEDNSOptionInQueryWithRecords(packet, newContent, ednsAdded, EDNSOptionCode::PADDING, edeAdded, true, false, padding)) {
    return false;
  }

  if (newContent.size() > maximumPacketSize) {
    return false;
  }

  packet = std::move(newContent);
  return true;
}

bool replaceEDNSPadding(PacketBuffer& packet, size_t maximumPacketSize)
{
  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  if (locateEDNSOptRR(packet, &optStart, &optLen, &last) != 0) {
    return false;
  }

  if (!isEDNSOptionInOpt(packet, optStart, optLen, EDNSOptionCode::PADDING)) {
    return addEDNSPadding(packet, maximumPacketSize);
  }

  PacketBuffer newContent = packet;
  if (last) {
    const size_t existingOptLen = optLen;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (removeEDNSOptionFromOPT(reinterpret_cast<char*>(&newContent.at(optStart)), &optLen, EDNSOptionCode::PADDING) != 0) {
      return false;
    }
    newContent.resize(newContent.size() - (existingOptLen - optLen));
  }
  else {
    PacketBuffer rewrittenContent;
    if (rewriteResponseWithoutEDNSOption(newContent, EDNSOptionCode::PADDING, rewrittenContent) != 0) {
      return false;
    }
    newContent = std::move(rewrittenContent);
  }

  if (!addEDNSPadding(newContent, maximumPacketSize)) {
    return false;
  }

  packet = std::move(newContent);
  return true;
}

} // namespace dnsdist::edns
