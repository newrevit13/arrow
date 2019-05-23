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

#ifndef PARQUET_UTIL_CRYPTO_H
#define PARQUET_UTIL_CRYPTO_H

#include <list>
#include <memory>
#include <string>

#include <openssl/evp.h>
#include "parquet/properties.h"
#include "parquet/types.h"

using parquet::ParquetCipher;

namespace parquet_encryption {

constexpr int GCMTagLength = 16;
constexpr int NonceLength = 12;

// Module types
const int8_t Footer = 0;
const int8_t ColumnMetaData = 1;
const int8_t DataPage = 2;
const int8_t DictionaryPage = 3;
const int8_t DataPageHeader = 4;
const int8_t DictionaryPageHeader = 5;
const int8_t ColumnIndex = 6;
const int8_t OffsetIndex = 7;

class AesEncryptor {
 public:
  // Can serve one key length only. Possible values: 16, 24, 32 bytes.
  AesEncryptor(ParquetCipher::type alg_id, int key_len, bool metadata,
               std::shared_ptr<std::list<AesEncryptor*>> all_encryptors);

  // Size different between plaintext and ciphertext, for this cipher.
  int CiphertextSizeDelta();

  // Key length is passed only for validation. If different from value in
  // constructor, exception will be thrown.
  int Encrypt(const uint8_t* plaintext, int plaintext_len, uint8_t* key, int key_len,
              uint8_t* aad, int aad_len, uint8_t* ciphertext);

  int SignedFooterEncrypt(const uint8_t* footer, int footer_len, uint8_t* key,
                          int key_len, uint8_t* aad, int aad_len, uint8_t* nonce,
                          uint8_t* encrypted_footer);

  void WipeOut() {
    if (NULLPTR != ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = NULLPTR;
    }
  }

  ~AesEncryptor() {
    if (NULLPTR != ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = NULLPTR;
    }
  }

 private:
  EVP_CIPHER_CTX* ctx_;
  int aes_mode_;
  int key_length_;
  int ciphertext_size_delta_;

  int gcm_encrypt(const uint8_t* plaintext, int plaintext_len, uint8_t* key, int key_len,
                  uint8_t* nonce, uint8_t* aad, int aad_len, uint8_t* ciphertext);

  int ctr_encrypt(const uint8_t* plaintext, int plaintext_len, uint8_t* key, int key_len,
                  uint8_t* nonce, uint8_t* ciphertext);
};

class AesDecryptor {
 public:
  // Can serve one key length only. Possible values: 16, 24, 32 bytes.
  AesDecryptor(ParquetCipher::type alg_id, int key_len, bool metadata,
               std::shared_ptr<std::list<AesDecryptor*>> all_decryptors);

  void WipeOut() {
    if (NULLPTR != ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = NULLPTR;
    }
  }

  // Size different between plaintext and ciphertext, for this cipher.
  int CiphertextSizeDelta();

  // Key length is passed only for validation. If different from value in
  // constructor, exception will be thrown.
  int Decrypt(const uint8_t* ciphertext, int ciphertext_len, uint8_t* key, int key_len,
              uint8_t* aad, int aad_len, uint8_t* plaintext);

  ~AesDecryptor() {
    if (NULLPTR != ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = NULLPTR;
    }
  }

 private:
  EVP_CIPHER_CTX* ctx_;
  int aes_mode_;
  int key_length_;
  int ciphertext_size_delta_;

  int gcm_decrypt(const uint8_t* ciphertext, int ciphertext_len, uint8_t* key,
                  int key_len, uint8_t* aad, int aad_len, uint8_t* plaintext);

  int ctr_decrypt(const uint8_t* ciphertext, int ciphertext_len, uint8_t* key,
                  int key_len, uint8_t* plaintext);
};

std::string createModuleAAD(const std::string& fileAAD, int8_t module_type,
                            int16_t row_group_ordinal, int16_t column_ordinal,
                            int16_t page_ordinal);

std::string createFooterAAD(const std::string& aad_prefix_bytes);

// Update last two bytes of page (or page header) module AAD
void quickUpdatePageAAD(const std::string& AAD, int16_t new_page_ordinal);

}  // namespace parquet_encryption

#endif  // PARQUET_UTIL_CRYPTO_H
