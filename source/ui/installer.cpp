#include <processes/pxi_fs.hpp>

#include <platform/file_formats/cia.hpp>
#include <platform/crypto.hpp>

#include <framework/exceptions.hpp>
#include <framework/formats.hpp>
#include <framework/ranges.hpp>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <range/v3/algorithm/equal.hpp>
#include <range/v3/view/zip.hpp>

#include <filesystem>

#include <fmt/ranges.h>

namespace HLE::PXI {
std::array<uint8_t, 16> GenerateAESKey(const std::array<uint8_t, 16>& key_x, const std::array<uint8_t, 16>& key_y);
}

template<typename T, typename SubType, typename Stream>
T ParseSignedData(Stream& reader) {
    auto sig = FileFormat::Signature { FileFormat::LoadValue<uint32_t, boost::endian::order::big>(reader), {} };

    sig.data.resize(FileFormat::GetSignatureSize(sig.type));
    reader(reinterpret_cast<char*>(sig.data.data()), sig.data.size() * sizeof(sig.data[0]));
    size_t pad_size;
    switch (sig.type) {
    case 0x10000:
    case 0x10001:
    case 0x10003:
    case 0x10004:
        pad_size = 0x3c;
        break;

    case 0x10002:
    case 0x10005:
        pad_size = 0x40;
        break;

    default:
        throw Mikage::Exceptions::Invalid("Unknown signature type {:#x}", sig.type);
    }
    std::vector<char> zeroes(pad_size, 0);
    reader(zeroes.data(), zeroes.size());

    return T { sig, FileFormat::SerializationInterface<SubType>::Load(reader) };
}

struct CIA {
    FileFormat::CIAHeader header;

    std::array<FileFormat::Certificate, 3> certificates;
    FileFormat::Ticket ticket;
    FileFormat::TMD tmd;

    std::vector<std::vector<uint8_t>> contents;

    FileFormat::CIAMeta meta;
};

void InstallCIA(std::filesystem::path content_dir, spdlog::logger& logger, const KeyDatabase& keydb, HLE::PXI::FS::FileContext& file_context, HLE::PXI::FS::File& file) {
    auto cia_offset = uint64_t{0};
    auto read_file = [&](char* dest, size_t size) {
        file.Read(file_context, cia_offset, static_cast<uint32_t>(size), HLE::PXI::FS::FileBufferInHostMemory { dest, static_cast<uint32_t>(size) });
        cia_offset += size;
    };

    auto header = FileFormat::SerializationInterface<FileFormat::CIAHeader>::Load(read_file);

    logger.info("CIA header size: {:#x}", header.header_size);
    logger.info("  Type: {:#x}", header.type);
    logger.info("  Version: {:#x}", header.version);
    logger.info("  Certificate chain size: {:#x}", header.certificate_chain_size);
    logger.info("  Ticket size: {:#x}", header.ticket_size);
    logger.info("  TMD size: {:#x}", header.tmd_size);
    logger.info("  Meta size: {:#x}", header.meta_size);
    logger.info("  Content size: {:#x}", header.content_size);

    if (header.header_size != FileFormat::CIAHeader::Tags::expected_serialized_size + 0x2000 /* content mask size */) {
        throw Mikage::Exceptions::NotImplemented("Unexpected CIA header size {:#x}", header.header_size);
    }
    if (header.version != 0) {
        throw Mikage::Exceptions::NotImplemented("Unexpected CIA version {:#x}", header.version);
    }

    std::vector<uint8_t> content_mask(0x2000);
    read_file(reinterpret_cast<char*>(content_mask.data()), content_mask.size());
    logger.info("  Content indexes:");
    for (auto byte_index : ranges::views::indexes(content_mask)) {
        for (int bit_index = 0; bit_index < 8; ++bit_index) {
            if (content_mask[byte_index] & (0x80 >> bit_index)) {
                logger.info("    {}", byte_index * 8 + bit_index);
            }
        }
    }

    // Data sections are aligned to 64 bytes
    const auto cert_begin = (header.header_size + 63) & ~uint64_t { 63 };
    const auto ticket_begin = cert_begin + ((header.certificate_chain_size + 63) & ~uint64_t { 63 });
    const auto tmd_begin = ticket_begin + ((header.ticket_size + 63) & ~uint64_t { 63 });
    const auto content_begin = tmd_begin + ((header.tmd_size + 63) & ~uint64_t { 63 });
    const auto meta_begin = content_begin + ((header.content_size + 63) & ~uint64_t { 63 });
    static_assert(sizeof(meta_begin) == 8);

    CIA ret;

    // Certificates
    cia_offset = cert_begin;
    auto& certificates = ret.certificates;
    for (auto cert_index : { 0, 1, 2}) {
        auto& certificate = certificates[cert_index];
        certificate = ParseSignedData<FileFormat::Certificate, FileFormat::Certificate::Data>(read_file);
        logger.info("Certificate {}:", cert_index);
        logger.info("  Type: {:#x}", certificate.sig.type);
        logger.info("  Public key type: {:#x}", certificate.cert.key_type);
        logger.info("  Issuer: {:c}", fmt::join(certificate.cert.issuer, ""));
        logger.info("  Name: {:c}", fmt::join(certificate.cert.name, ""));

        if (certificate.cert.key_type == 0) {
            certificate.pubkey.rsa4096 = FileFormat::SerializationInterface<FileFormat::CertificatePublicKey::RSAKey<4096/8>>::Load(read_file);
        } else if (certificate.cert.key_type == 1) {
            certificate.pubkey.rsa2048 = FileFormat::SerializationInterface<FileFormat::CertificatePublicKey::RSAKey<2048/8>>::Load(read_file);
        } else if (certificate.cert.key_type == 1) {
            certificate.pubkey.ecc = FileFormat::SerializationInterface<FileFormat::CertificatePublicKey::ECCKey>::Load(read_file);
        } else {
            throw std::runtime_error("Unknown certificate public key type");
        }
    }

    // Ticket
    logger.info("Ticket:");
    cia_offset = ticket_begin;
    ret.ticket = ParseSignedData<FileFormat::Ticket, FileFormat::Ticket::Data>(read_file);
    auto& ticket = ret.ticket;
    logger.info("  Signature type: {:#x}", ticket.sig.type);
    logger.info("  Issuer: {:c}", fmt::join(ticket.data.issuer, ""));
    logger.info("  Format version: {:#x}", ticket.data.version);
    logger.info("  Ticket ID: {:#x}", ticket.data.ticket_id);
    logger.info("  Console ID: {:#x}", ticket.data.console_id);
    logger.info("  Title ID: {:#x}", ticket.data.title_id);
    logger.info("  Sys Access: {:#x}", ticket.data.sys_access);
    logger.info("  Title version: {:#x}", ticket.data.title_version);
    logger.info("  Permit mask: {:#x}", ticket.data.permit_mask);
    logger.info("  Title export: {:#x}", ticket.data.title_export);
    logger.info("  KeyY index: {:#x}", ticket.data.key_y_index);
    for (uint32_t i = 0; i < ticket.data.time_limit.size(); ++i) {
        if (ticket.data.time_limit[i].enable) {
            logger.info("  Time limit {}: {} seconds", i, ticket.data.time_limit[i].limit_in_seconds);
        }
    }
    logger.info("  Unknown @ 0: {:#x}", ticket.data.unknown[0]);
    logger.info("  Unknown @ 1: {:#x}", ticket.data.unknown[1]);
    logger.info("  Unknown: {:#x}", ticket.data.unknown2);
    for (size_t i = 0; i < ticket.data.unknown3.size(); ++i) {
        if (ticket.data.unknown3[i]) {
            logger.info("  Unknown3 @ {}: {:#x}", i, ticket.data.unknown3[i]);
        }
    }
    for (size_t i = 0; i < ticket.data.unknown4.size(); ++i) {
        if (ticket.data.unknown4[i]) {
            logger.info("  Unknown4 @ {}: {:#x}", i, ticket.data.unknown4[i]);
        }
    }

    // TMD
    logger.info("TMD: ");

    cia_offset = tmd_begin;

    ret.tmd = ParseSignedData<FileFormat::TMD, FileFormat::TMD::Data>(read_file);
    auto& tmd = ret.tmd;

    logger.info("  Signature type: {:#x}", tmd.sig.type);
    logger.info("  Issuer: {:c}", fmt::join(tmd.data.issuer, ""));
    logger.info("  Version: {:#x}", tmd.data.version);
    logger.info("  CA revocation list version: {:#x}", tmd.data.ca_crl_version);
    logger.info("  Signer CLR version: {:#x}", tmd.data.ca_crl_version);
    logger.info("  System version: {:#x}", tmd.data.system_version);
    logger.info("  Title id: {:#x}", tmd.data.title_id);
    logger.info("  Title type: {:#x}", tmd.data.title_type);
    logger.info("  Group id: {:#x}", tmd.data.group_id);
    logger.info("  Save data size: {:#x}", tmd.data.save_data_size);
    logger.info("  Private save data size for SRL: {:#x}", tmd.data.srl_private_data_size);
    logger.info("  SRL flag: {:#x}", tmd.data.srl_flag);
    logger.info("  Access rights: {:#x}", tmd.data.access_rights);
    logger.info("  Title version: {:#x}", tmd.data.title_version);
    logger.info("  Content count: {:#x}", tmd.data.content_count);
    logger.info("  Main content: {:#x}", tmd.data.main_content);

    logger.info("  Unknown: {:#x}", tmd.data.unknown);
    logger.info("  Unknown2: {:#x}", tmd.data.unknown2);
    for (size_t i = 0; i < tmd.data.unknown3.size(); ++i) {
        if (tmd.data.unknown3[i]) {
            logger.info("  Unknown3 @ {}: {:#x}", i, tmd.data.unknown3[i]);
        }
    }
    logger.info("  Unknown4: {:#x}", tmd.data.unknown4);

    // TMD content info
    {
        // Read raw content infos into memory for hashing first
        std::vector<char> content_info_hash_data(FileFormat::TMD::ContentInfoHash::Tags::expected_serialized_size * tmd.content_info_hashes.size());
        read_file(content_info_hash_data.data(), content_info_hash_data.size());

        // Get content info hash ... hash
        CryptoPP::byte contentinfohash_hash[CryptoPP::SHA256::DIGESTSIZE];
        CryptoPP::SHA256().CalculateDigest(contentinfohash_hash,
                                           reinterpret_cast<const CryptoPP::byte*>(content_info_hash_data.data()), content_info_hash_data.size());
        logger.info("  Reference hash: {:02x}", fmt::join(ret.tmd.data.content_info_records_sha256, ""));
        logger.info("  Computed hash:  {:02x}", fmt::join(contentinfohash_hash, ""));
        if (!ranges::equal(ret.tmd.data.content_info_records_sha256, contentinfohash_hash)) {
            throw std::runtime_error("Hash over TMD content info hashes doesn't match reference");
        }

        auto stream = FileFormat::MakeStreamInFromContainer(content_info_hash_data);
        for (auto& content_info_hash : tmd.content_info_hashes) {
            content_info_hash = FileFormat::SerializationInterface<FileFormat::TMD::ContentInfoHash>::Load(stream);
        }
    }

    {
        std::vector<char> content_info_data(FileFormat::TMD::ContentInfo::Tags::expected_serialized_size * tmd.data.content_count);
        read_file(content_info_data.data(), content_info_data.size());

        {
            std::size_t content_info_index = 0;
            for (auto& content_info_hash : tmd.content_info_hashes) {
                if (content_info_hash.chunk_count == 0) {
                    continue;
                }

                // TODO: Should the given index_offset be used instead of content_info_index?
                if (content_info_hash.index_offset != content_info_index) {
                    throw Mikage::Exceptions::Invalid("Unknown behavior for TMD content info offset");
                }

                // Hash "chunk_count" content infos
                CryptoPP::byte contentinfo_hash[CryptoPP::SHA256::DIGESTSIZE];
                auto data_ptr_for_hash = &content_info_data[content_info_index];
                uint64_t bytes_to_hash = content_info_hash.chunk_count * FileFormat::TMD::ContentInfo::Tags::expected_serialized_size;
                CryptoPP::SHA256().CalculateDigest(contentinfo_hash,
                                                   reinterpret_cast<const CryptoPP::byte*>(data_ptr_for_hash), bytes_to_hash);
                logger.info("  Hashes covering content info {}-{}:", content_info_hash.index_offset, content_info_hash.index_offset + content_info_hash.chunk_count - 1);
                logger.info("    Reference: {:02x}", fmt::join(content_info_hash.sha256, ""));
                logger.info("    Computed:  {:02x}", fmt::join(contentinfo_hash, ""));
                if (!ranges::equal(content_info_hash.sha256, contentinfo_hash)) {
                    throw std::runtime_error("Hash over TMD content info doesn't match reference");
                }

                content_info_index += content_info_hash.chunk_count;
            }
        }

        tmd.content_infos.resize(tmd.data.content_count);
        auto stream = FileFormat::MakeStreamInFromContainer(content_info_data);
        uint64_t total_content_size = 0;
        for (const auto& content_info_index : ranges::views::indexes(tmd.content_infos)) {
            logger.info("  Content info {}", content_info_index);
            auto& content_info = tmd.content_infos[content_info_index];
            content_info = FileFormat::SerializationInterface<FileFormat::TMD::ContentInfo>::Load(stream);

            logger.info("    Index: {}", content_info.index);
            logger.info("    Id: {}", content_info.id);
            logger.info("    Size: {:#x}", content_info.size);
            logger.info("    Flags:{}", content_info.type == 0 ? " (none)" : "");
            if (content_info.type & 1) {
                logger.info("      encrypted");
            }
            if (content_info.type > 1) {
                logger.info("      unknown ({:#x})", content_info.type);
            }

            if ((content_info.index / 8 > content_mask.size()) ||
                (content_mask[content_info.index / 8] & (~content_info.index % 8)) == 0) {
                throw Mikage::Exceptions::Invalid("TMD content index not present in CIA content mask");
            }

            total_content_size += content_info.size;
        }

        if (total_content_size != header.content_size) {
            throw Mikage::Exceptions::Invalid("Sum of TMD content sizes doesn't match CIA content size");
        }
    }

    if (cia_offset != tmd_begin + header.tmd_size) {
        throw Mikage::Exceptions::Invalid("TMD ended at unexpected offset");
    }


    // Content
    logger.info("Content:");
    cia_offset = content_begin;

    for (const auto& content_info : ret.tmd.content_infos) {
        std::vector<uint8_t> ncch(content_info.size);
        read_file(reinterpret_cast<char*>(ncch.data()), ncch.size());

        if (content_info.type & 1) {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;

            // Decrypt title key using common key
            auto title_key = ret.ticket.data.title_key_encrypted;
            {
                const auto& common_key_x = keydb.aes_slots[0x3d].x.value();
                const auto& common_key_y = keydb.common_y.at(ret.ticket.data.key_y_index).value();
                auto common_key = HLE::PXI::GenerateAESKey(common_key_x, common_key_y);

                // IV is the title ID encoded as big-endian
                std::array<uint8_t, 0x10> iv {};
                memcpy(iv.data(), &ret.ticket.data.title_id, sizeof(ret.ticket.data.title_id));
                std::reverse(iv.begin(), iv.begin() + sizeof(ret.ticket.data.title_id));
                dec.SetKeyWithIV(common_key.data(), sizeof(common_key), iv.data());
                dec.ProcessData(reinterpret_cast<CryptoPP::byte*>(title_key.data()), reinterpret_cast<const CryptoPP::byte*>(title_key.data()), title_key.size());
            }

            // Decrypt content using decrypted title key
            {
                // IV is the content ID encoded as big-endian
                std::array<uint8_t, 0x10> iv {};
                memcpy(iv.data(), &content_info.index, sizeof(content_info.index));
                std::reverse(iv.begin(), iv.begin() + sizeof(content_info.index));
                dec.SetKeyWithIV(title_key.data(), sizeof(title_key), iv.data());
                dec.ProcessData(reinterpret_cast<CryptoPP::byte*>(ncch.data()), reinterpret_cast<const CryptoPP::byte*>(ncch.data()), ncch.size());
            }
        }

        CryptoPP::byte content_hash[CryptoPP::SHA256::DIGESTSIZE];
        CryptoPP::SHA256().CalculateDigest(content_hash,
                                           reinterpret_cast<const CryptoPP::byte*>(ncch.data()), ncch.size());

        logger.info("  Reference content hash: {:02x}", fmt::join(content_info.sha256, ""));
        logger.info("  Computed content hash:  {:02x}", fmt::join(content_hash, ""));

        if (!ranges::equal(content_info.sha256, content_hash)) {
            throw std::runtime_error("Content hash doesn't match TMD");
        }

        ret.contents.push_back(std::move(ncch));
    }

    logger.info("Beginning install...\n");

    uint32_t title_id_high = ret.ticket.data.title_id >> 32;
    uint32_t title_id_low = ret.ticket.data.title_id & 0xffffffff;
    content_dir /= fmt::format("{:08x}/{:08x}/content", title_id_high, title_id_low);
    std::filesystem::create_directories(content_dir);

//    // TODO: Implement TMD writing
//    {
//        // TODO: If a TMD already exists, remove it and use its incremented number here
//        std::ofstream file(content_dir / fmt::format("{:x}.tmd", 0));
//    }

    for (auto content_index = 0; content_index < ret.contents.size(); ++content_index) {
        const auto& ncch = ret.contents[content_index];
        const auto& content_info = ret.tmd.content_infos.at(content_index);

        std::ofstream out_file(content_dir / fmt::format("{:08x}.cxi", content_info.id));
        out_file.write(reinterpret_cast<const char*>(ncch.data()), ncch.size());

        // To simplify title launching, we always boot from 00000000.cxi currently.
        // Copy the main title to that location hence
        // TODO: Read TMD when launching titles instead
        if (content_index == ret.tmd.data.main_content) {
            if (content_info.id != 0) {
                std::filesystem::copy(content_dir / fmt::format("{:08x}.cxi", content_info.id), content_dir / fmt::format("00000000.cxi"), std::filesystem::copy_options::overwrite_existing);
            }
        } else if (content_info.id == 0) {
            throw Mikage::Exceptions::NotImplemented("Content id 0 expected to be the main content");
        }
    }

    // TODO: If title id is native firm, extract its files...

//    // Meta
//    file.seekg(meta_begin);
//    strbuf_it = std::istreambuf_iterator<char>(file.rdbuf());
//    stream = FileFormat::MakeStreamInFromContainer(strbuf_it, decltype(strbuf_it){});
//    ret.meta = FileFormat::Load<FileFormat::CIAMeta>(stream);
//    for (auto& title_id : ret.meta.dependencies) {
//        if (!title_id)
//            continue;

//        std::cout << "Dependency: " << std::hex << std::setw(16) << std::setfill('0') << title_id << std::endl;
//    }

    logger.info("");
}
