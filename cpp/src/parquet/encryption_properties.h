// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#ifndef PARQUET_ENCRYPTION_PROPERTIES_H
#define PARQUET_ENCRYPTION_PROPERTIES_H

#include <map>
#include <memory>
#include <string>
#include <unordered_map>

#include "arrow/util/logging.h"
#include "parquet/encryption.h"
#include "parquet/exception.h"
#include "parquet/schema.h"
#include "parquet/types.h"
#include "parquet/util/visibility.h"

namespace parquet {

static const std::string NULL_STRING = "";
static constexpr ParquetCipher::type DEFAULT_ENCRYPTION_ALGORITHM =
    ParquetCipher::AES_GCM_V1;
static constexpr int32_t MAXIMAL_AAD_METADATA_LENGTH = 256;
static constexpr bool DEFAULT_ENCRYPTED_FOOTER = true;
static constexpr bool DEFAULT_CHECK_SIGNATURE = true;
static constexpr int32_t AAD_FILE_UNIQUE_LENGTH = 8;

class PARQUET_EXPORT ColumnEncryptionProperties {
 public:
  class Builder {
   public:
    // Convenience builder for regular (not nested) columns.
    explicit Builder(const std::string& name) {
      Builder(schema::ColumnPath::FromDotString(name), true);
    }

    // Convenience builder for encrypted columns.
    explicit Builder(const std::shared_ptr<schema::ColumnPath>& path)
        : Builder(path, true) {}

    // Set a column-specific key.
    // If key is not set on an encrypted column, the column will
    // be encrypted with the footer key.
    // keyBytes Key length must be either 16, 24 or 32 bytes.
    Builder* key(const std::string& key) {
      if (key.empty()) return this;

      DCHECK(!key.empty());
      key_ = key;
      return this;
    }

    // Set a key retrieval metadata.
    // use either key_metadata() or key_id(), not both
    Builder* key_metadata(const std::string& key_metadata) {
      DCHECK(!key_metadata.empty());
      DCHECK(key_metadata_.empty());
      key_metadata_ = key_metadata;
      return this;
    }

    // Set a key retrieval metadata (converted from String).
    // use either key_metadata() or key_id(), not both
    // key_id will be converted to metadata (UTF-8 array).
    Builder* key_id(const std::string& key_id);

    std::shared_ptr<ColumnEncryptionProperties> build() {
      return std::shared_ptr<ColumnEncryptionProperties>(
          new ColumnEncryptionProperties(encrypted_, column_path_, key_, key_metadata_));
    }

   private:
    const std::shared_ptr<schema::ColumnPath> column_path_;
    bool encrypted_;
    std::string key_;
    std::string key_metadata_;

    Builder(const std::shared_ptr<schema::ColumnPath>& path, bool encrypted)
        : column_path_(path), encrypted_(encrypted) {}
  };

  const std::shared_ptr<schema::ColumnPath>& column_path() { return column_path_; }
  bool is_encrypted() const { return encrypted_; }
  bool is_encrypted_with_footer_key() const { return encrypted_with_footer_key_; }
  const std::string& key() const { return key_; }
  const std::string& key_metadata() const { return key_metadata_; }

  ColumnEncryptionProperties() = default;
  ColumnEncryptionProperties(const ColumnEncryptionProperties& other) = default;
  ColumnEncryptionProperties(ColumnEncryptionProperties&& other) = default;

 private:
  const std::shared_ptr<schema::ColumnPath> column_path_;
  bool encrypted_;
  bool encrypted_with_footer_key_;
  std::string key_;
  std::string key_metadata_;
  explicit ColumnEncryptionProperties(
      bool encrypted, const std::shared_ptr<schema::ColumnPath>& column_path,
      const std::string& key, const std::string& key_metadata);
};

class PARQUET_EXPORT ColumnDecryptionProperties {
 public:
  class Builder {
   public:
    // convenience builder for regular (not nested) columns.
    explicit Builder(const std::string& name)
        : Builder(schema::ColumnPath::FromDotString(name)) {}

    explicit Builder(const std::shared_ptr<schema::ColumnPath>& path)
        : column_path_(path) {}

    // Set an explicit column key. If applied on a file that contains
    // key metadata for this column the metadata will be ignored,
    // the column will be decrypted with this key.
    // key length must be either 16, 24 or 32 bytes.
    Builder* key(const std::string& key) {
      if (key.empty()) return this;

      DCHECK(!key.empty());
      key_ = key;
      return this;
    }

    std::shared_ptr<ColumnDecryptionProperties> build() {
      return std::shared_ptr<ColumnDecryptionProperties>(
          new ColumnDecryptionProperties(column_path_, key_));
    }

   private:
    const std::shared_ptr<schema::ColumnPath> column_path_;
    std::string key_;
  };

  ColumnDecryptionProperties() = default;
  ColumnDecryptionProperties(const ColumnDecryptionProperties& other) = default;
  ColumnDecryptionProperties(ColumnDecryptionProperties&& other) = default;

  const std::shared_ptr<schema::ColumnPath>& column_path() { return column_path_; }
  const std::string& key() const { return key_; }

 private:
  const std::shared_ptr<schema::ColumnPath> column_path_;
  std::string key_;

  // This class is only required for setting explicit column decryption keys -
  // to override key retriever (or to provide keys when key metadata and/or
  // key retriever are not available)
  explicit ColumnDecryptionProperties(
      const std::shared_ptr<schema::ColumnPath>& column_path, const std::string& key);
};

class PARQUET_EXPORT AADPrefixVerifier {
 public:
  // Verifies identity (AAD Prefix) of individual file,
  // or of file collection in a data set.
  // Throws exception if an AAD prefix is wrong.
  // In a data set, AAD Prefixes should be collected,
  // and then checked for missing files.
  virtual void check(const std::string& aad_prefix) = 0;
};

class PARQUET_EXPORT FileDecryptionProperties {
 public:
  class Builder {
   public:
    Builder() { check_plaintext_footer_integrity_ = DEFAULT_CHECK_SIGNATURE; }

    // Set an explicit footer key. If applied on a file that contains
    // footer key metadata the metadata will be ignored, the footer
    // will be decrypted/verified with this key.
    // If explicit key is not set, footer key will be fetched from
    // key retriever.
    // param footerKey Key length must be either 16, 24 or 32 bytes.
    Builder* footer_key(const std::string& footer_key) {
      if (footer_key.empty()) {
        return this;
      }
      DCHECK(!footer_key.empty());
      footer_key_ = footer_key;
      return this;
    }

    // Set explicit column keys (decryption properties).
    // Its also possible to set a key retriever on this property object.
    // Upon file decryption, availability of explicit keys is checked before
    // invocation of the retriever callback.
    // If an explicit key is available for a footer or a column,
    // its key metadata will be ignored.
    Builder* column_properties(
        const std::map<std::shared_ptr<schema::ColumnPath>,
                       std::shared_ptr<ColumnDecryptionProperties>,
                       schema::ColumnPath::CmpColumnPath>& column_properties) {
      if (column_properties.size() == 0) return this;

      if (column_properties_.size() != 0)
        throw ParquetException("Column properties already set");

      column_properties_ = column_properties;
      return this;
    }

    // Set a key retriever callback. Its also possible to
    // set explicit footer or column keys on this file property object.
    // Upon file decryption, availability of explicit keys is checked before
    // invocation of the retriever callback.
    // If an explicit key is available for a footer or a column,
    // its key metadata will be ignored.
    Builder* key_retriever(const std::shared_ptr<DecryptionKeyRetriever>& key_retriever) {
      if (key_retriever == NULLPTR) return this;

      DCHECK(key_retriever_ == NULLPTR);
      key_retriever_ = key_retriever;
      return this;
    }

    // Skip integrity verification of plaintext footers.
    // If not called, integrity of plaintext footers will be checked in runtime,
    // and an exception will be thrown in the following situations:
    // - footer signing key is not available
    // (not passed, or not found by key retriever)
    // - footer content and signature don't match
    Builder* disable_footer_signature_verification() {
      check_plaintext_footer_integrity_ = false;
      return this;
    }

    // Explicitly supply the file AAD prefix.
    // A must when a prefix is used for file encryption, but not stored in file.
    // If AAD prefix is stored in file, it will be compared to the explicitly
    // supplied value and an exception will be thrown if they differ.
    Builder* aad_prefix(const std::string& aad_prefix) {
      if (aad_prefix.empty()) {
        return this;
      }
      DCHECK(aad_prefix_.empty());
      aad_prefix_ = aad_prefix;
      return this;
    }

    // Set callback for verification of AAD Prefixes stored in file.
    Builder* aad_prefix_verifier(std::shared_ptr<AADPrefixVerifier> aad_prefix_verifier) {
      if (aad_prefix_verifier == NULLPTR) return this;

      DCHECK(aad_prefix_verifier_ == NULLPTR);
      aad_prefix_verifier_ = aad_prefix_verifier;
      return this;
    }

    std::shared_ptr<FileDecryptionProperties> build() {
      return std::shared_ptr<FileDecryptionProperties>(new FileDecryptionProperties(
          footer_key_, key_retriever_, check_plaintext_footer_integrity_, aad_prefix_,
          aad_prefix_verifier_, column_properties_));
    }

   private:
    std::string footer_key_;
    std::string aad_prefix_;
    std::shared_ptr<AADPrefixVerifier> aad_prefix_verifier_;

    std::map<std::shared_ptr<schema::ColumnPath>,
             std::shared_ptr<ColumnDecryptionProperties>,
             schema::ColumnPath::CmpColumnPath>
        column_properties_;

    std::shared_ptr<DecryptionKeyRetriever> key_retriever_;
    bool check_plaintext_footer_integrity_;
  };

  const std::string& column_key(const std::shared_ptr<schema::ColumnPath>& column_path);

  const std::string& footer_key() { return footer_key_; }

  const std::string& aad_prefix() { return aad_prefix_; }
  std::shared_ptr<DecryptionKeyRetriever> key_retriever() { return key_retriever_; }

  bool check_plaintext_footer_integrity() { return check_plaintext_footer_integrity_; }

  const std::shared_ptr<AADPrefixVerifier>& aad_prefix_verifier() {
    return aad_prefix_verifier_;
  }

 private:
  std::string footer_key_;
  std::string aad_prefix_;
  std::shared_ptr<AADPrefixVerifier> aad_prefix_verifier_;

  std::map<std::shared_ptr<schema::ColumnPath>,
           std::shared_ptr<ColumnDecryptionProperties>, schema::ColumnPath::CmpColumnPath>
      column_properties_;

  std::shared_ptr<DecryptionKeyRetriever> key_retriever_;
  bool check_plaintext_footer_integrity_;

  FileDecryptionProperties(
      const std::string& footer_key,
      const std::shared_ptr<DecryptionKeyRetriever>& key_retriever,
      bool check_plaintext_footer_integrity, const std::string& aad_prefix,
      std::shared_ptr<AADPrefixVerifier> aad_prefix_verifier,
      const std::map<std::shared_ptr<schema::ColumnPath>,
                     std::shared_ptr<ColumnDecryptionProperties>,
                     schema::ColumnPath::CmpColumnPath>& column_properties);
};

class PARQUET_EXPORT FileEncryptionProperties {
 public:
  class Builder {
   public:
    explicit Builder(const std::string& footer_key)
        : parquet_cipher_(DEFAULT_ENCRYPTION_ALGORITHM),
          encrypted_footer_(DEFAULT_ENCRYPTED_FOOTER) {
      footer_key_ = footer_key;
      store_aad_prefix_in_file_ = false;
    }

    // Create files with plaintext footer.
    // If not called, the files will be created with encrypted footer (default).
    Builder* enable_plaintext_footer() {
      encrypted_footer_ = false;
      return this;
    }

    // Set encryption algorithm.
    // If not called, files will be encrypted with AES_GCM_V1 (default).
    Builder* algorithm(ParquetCipher::type parquet_cipher) {
      parquet_cipher_ = parquet_cipher;
      return this;
    }

    // Set a key retrieval metadata (converted from String).
    // use either footer_key_metadata or footer_key_id, not both.
    Builder* footer_key_id(const std::string& key_id);

    // Set a key retrieval metadata.
    // use either footer_key_metadata or footer_key_id, not both.
    Builder* footer_key_metadata(const std::string& footer_key_metadata) {
      if (footer_key_metadata.empty()) return this;

      DCHECK(footer_key_metadata_.empty());
      footer_key_metadata_ = footer_key_metadata;
      return this;
    }

    // Set the file AAD Prefix.
    Builder* aad_prefix(const std::string& aad_prefix) {
      if (aad_prefix.empty()) return this;

      DCHECK(aad_prefix_.empty());
      aad_prefix_ = aad_prefix;
      store_aad_prefix_in_file_ = true;
      return this;
    }

    // Skip storing AAD Prefix in file.
    // If not called, and if AAD Prefix is set, it will be stored.
    Builder* disable_store_aad_prefix_storage() {
      DCHECK(!aad_prefix_.empty());

      store_aad_prefix_in_file_ = false;
      return this;
    }

    // Set the list of encrypted columns and their properties (keys etc).
    // If not called, all columns will be encrypted with the footer key.
    // If called, the file columns not in the list will be left unencrypted.
    Builder* column_properties(
        const std::map<std::shared_ptr<schema::ColumnPath>,
                       std::shared_ptr<ColumnEncryptionProperties>,
                       schema::ColumnPath::CmpColumnPath>& column_properties) {
      if (column_properties.size() == 0) return this;

      if (column_properties_.size() != 0)
        throw ParquetException("Column properties already set");

      column_properties_ = column_properties;
      return this;
    }

    std::shared_ptr<FileEncryptionProperties> build() {
      return std::shared_ptr<FileEncryptionProperties>(new FileEncryptionProperties(
          parquet_cipher_, footer_key_, footer_key_metadata_, encrypted_footer_,
          aad_prefix_, store_aad_prefix_in_file_, column_properties_));
    }

   private:
    ParquetCipher::type parquet_cipher_;
    bool encrypted_footer_;
    std::string footer_key_;
    std::string footer_key_metadata_;

    std::string aad_prefix_;
    bool store_aad_prefix_in_file_;
    std::map<std::shared_ptr<schema::ColumnPath>,
             std::shared_ptr<ColumnEncryptionProperties>,
             schema::ColumnPath::CmpColumnPath>
        column_properties_;
  };
  bool encrypted_footer() const { return encrypted_footer_; }

  const EncryptionAlgorithm algorithm() { return algorithm_; }

  const std::string& footer_encryption_key() {
    return (encrypted_footer_ ? footer_key_ : NULL_STRING);
  }

  const std::string& footer_encryption_key_metadata() {
    return (encrypted_footer_ ? footer_key_metadata_ : NULL_STRING);
  }

  const std::string& footer_signing_key() {
    return (encrypted_footer_ ? NULL_STRING : footer_key_);
  }

  const std::string& footer_signing_key_metadata() {
    return (encrypted_footer_ ? NULL_STRING : footer_key_metadata_);
  }

  const std::string& file_aad() const { return file_aad_; }

  std::shared_ptr<ColumnEncryptionProperties> column_properties(
      const std::shared_ptr<schema::ColumnPath>& column_path);

 private:
  EncryptionAlgorithm algorithm_;
  std::string footer_key_;
  std::string footer_key_metadata_;
  bool encrypted_footer_;
  std::string file_aad_;

  std::map<std::shared_ptr<schema::ColumnPath>,
           std::shared_ptr<ColumnEncryptionProperties>, schema::ColumnPath::CmpColumnPath>
      column_properties_;

  FileEncryptionProperties(
      ParquetCipher::type cipher, const std::string& footer_key,
      const std::string& footer_key_metadata, bool encrypted_footer,
      const std::string& aad_prefix, bool store_aad_prefix_in_file,
      const std::map<std::shared_ptr<schema::ColumnPath>,
                     std::shared_ptr<ColumnEncryptionProperties>,
                     schema::ColumnPath::CmpColumnPath>& column_properties);
};

}  // namespace parquet

#endif  // PARQUET_ENCRYPTION_PROPERTIES_H
