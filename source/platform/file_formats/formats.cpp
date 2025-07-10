#define FORMATS_IMPL_EXPLICIT_FORMAT_INSTANTIATIONS_INTENDED
#include <framework/formats_impl.hpp>

#include "3dsx.hpp"
#include "bcfnt.hpp"
#include "cia.hpp"
#include "dsp1.hpp"
#include "ncch.hpp"
#include "smdh.hpp"

namespace FileFormat {

// 3DSX structures
template struct SerializationInterface<Dot3DSX::Header>;
template struct SerializationInterface<Dot3DSX::RelocationHeader>;
template struct SerializationInterface<Dot3DSX::RelocationInfo>;

// BCFNT structures
template struct SerializationInterface<BCFNT::Header>;
template struct SerializationInterface<BCFNT::BlockCommon>;
template struct SerializationInterface<BCFNT::FINF>;
template struct SerializationInterface<BCFNT::CMAP>;
template struct SerializationInterface<BCFNT::CWDH>;
template struct SerializationInterface<BCFNT::TGLP>;

// CIA structures
template struct SerializationInterface<Certificate::Data>;
template struct SerializationInterface<CertificatePublicKey::RSAKey<2048/8>>;
template struct SerializationInterface<CertificatePublicKey::RSAKey<4096/8>>;
template struct SerializationInterface<CertificatePublicKey::ECCKey>;
template struct SerializationInterface<CIAHeader>;
template struct SerializationInterface<CIAMeta>;
template struct SerializationInterface<Ticket::Data>;
template struct SerializationInterface<TicketTimeLimit>;
template struct SerializationInterface<TMD::ContentInfo>;
template struct SerializationInterface<TMD::ContentInfoHash>;
template struct SerializationInterface<TMD::Data>;

// DSP structures
template struct SerializationInterface<DSPFirmwareHeader>;

// NCCH structures
template struct SerializationInterface<ExeFSHeader>;
template struct SerializationInterface<ExHeader>;
template struct SerializationInterface<NCCHHeader>;

// SMDH structures

template struct SerializationInterface<SMDH>;

template<>
uint32_t SerializationInterface<uint32_t>::Load(std::function<void(char*, size_t)> reader) {
    return ConstructFromReadCallback<uint32_t, detail::DefaultTags, std::tuple<uint32_t>>{}(reader);
}

template<>
uint64_t SerializationInterface<uint64_t>::Load(std::function<void(char*, size_t)> reader) {
    return ConstructFromReadCallback<uint64_t, detail::DefaultTags, std::tuple<uint64_t>>{}(reader);
}

template<>
boost::endian::little_uint32_t SerializationInterface<boost::endian::little_uint32_t>::Load(std::function<void(char*, size_t)> reader) {
    struct Tags : little_endian_tag {};
    return ConstructFromReadCallback<uint32_t, Tags, std::tuple<uint32_t>>{}(reader);
}

template<>
boost::endian::big_uint32_t SerializationInterface<boost::endian::big_uint32_t>::Load(std::function<void(char*, size_t)> reader) {
    struct Tags : big_endian_tag {};
    return ConstructFromReadCallback<uint32_t, Tags, std::tuple<uint32_t>>{}(reader);
}

template<>
void SerializationInterface<boost::endian::big_uint32_t>::Save(const boost::endian::big_uint32_t& data, std::function<void(char*, size_t)> writer) {
    struct Tags : big_endian_tag {};
    SaveWithWriteCallback<uint32_t, Tags, std::tuple<uint32_t>>{}(data, writer);
}

} // namespace FileFormat
