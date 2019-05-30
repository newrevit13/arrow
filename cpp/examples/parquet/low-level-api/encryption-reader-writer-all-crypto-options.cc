// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements. See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership. The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

#include <dirent.h>
#include <cassert>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

#include <reader_writer.h>

/*
 * This file contains samples for writing and reading encrypted Parquet files in different
 * encryption and decryption configurations. The samples have the following goals:
 * 1) Demonstrate usage of different options for data encryption and decryption.
 * 2) Produce encrypted files for interoperability tests with other (eg parquet-mr)
 *    readers
 * 3) Perform interoperability tests with other (eg parquet-mr) writers, by reading
 *    encrypted files produced by these writers.
 *
 * The write sample produces number of parquet files, each encrypted with a different
 * encryption configuration as described below.
 * The name of each file is in the form of:
 * sample<encryption config number>.parquet.encrypted.
 *
 * The read sample creates a set of decryption configurations and then uses each of them
 * to read all encrypted files in the input directory.
 *
 * The different encryption and decryption configurations are listed below.
 *
 * Usage: ./encryption-interop-tests <write/read> <path-to-directory-of-parquet-files>
 *
 * A detailed description of the Parquet Modular Encryption specification can be found
 * here:
 * https://github.com/apache/parquet-format/blob/encryption/Encryption.md
 *
 * The write sample creates files with eight columns in the following
 * encryption configurations:
 *
 *  - Encryption configuration 1:   Encrypt all columns and the footer with the same key.
 *                                  (uniform encryption)
 *  - Encryption configuration 2:   Encrypt two columns and the footer.
 *  - Encryption configuration 3:   Encrypt two columns. Don’t encrypt footer (to enable
 *                                  legacy readers) - plaintext footer mode.
 *  - Encryption configuration 4:   Encrypt two columns and the footer. Supply  aad_prefix
 *                                  for file identity verification.
 *  - Encryption configuration 5:   Encrypt two columns and the footer. Supply aad_prefix,
 *                                  and call disable_aad_prefix_storage to prevent file
 *                                  identity storage in file metadata.
 *  - Encryption configuration 6:   Encrypt two columns and the footer. Use the
 *                                  alternative (AES_GCM_CTR_V1) algorithm.
 *
 * The read sample uses each of the following decryption configurations to read every
 * encrypted files in the input directory:
 *
 *  - Decryption configuration 1:   Decrypt using key retriever that holds the keys of
 *                                  two encrypted columns and the footer key.
 *  - Decryption configuration 2:   Decrypt using key retriever that holds the keys of
 *                                  two encrypted columns and the footer key. Supplies
 *                                  aad_prefix to verify file identity.
 *  - Decryption configuration 3:   Decrypt using key retriever that holds the key of only
 *                                  one encrypted column and the footer key. This
 *                                  configuration will throw a HiddenColumn exception.
 *                                  Supplies aad_prefix.
 *  - Decryption configuration 4:   Decrypt using explicit column and footer keys
 *                                  (instead of key retrieval callback).
 *                                  Supplies aad_prefix.
 */

constexpr int NUM_ROWS_PER_ROW_GROUP = 500;

const std::string kFooterEncryptionKey = "0123456789012345";  // 128bit/16
const std::string kColumnEncryptionKey1 = "1234567890123450";
const std::string kColumnEncryptionKey2 = "1234567890123451";
const std::string fileName = "tester";

std::vector<std::string> GetDirectoryFiles(const std::string& path) {
  std::vector<std::string> files;
  struct dirent* entry;
  DIR* dir = opendir(path.c_str());

  if (dir == NULL) {
    exit(-1);
  }
  while ((entry = readdir(dir)) != NULL) {
    files.push_back(std::string(entry->d_name));
  }
  closedir(dir);
  return files;
}

void PrintDecryptionConfiguration(int configuration) {
  std::cout << "\n\nDecryption configuration ";
  if (configuration == 1)
    std::cout << "1: \n\nDecrypt using key retriever that holds"
                 " the keys of two encrypted columns and the footer key."
              << std::endl;
  else if (configuration == 2)
    std::cout << "2: \n\nDecrypt using key retriever that holds"
                 " the keys of two encrypted columns and the footer key. Pass aad_prefix."
              << std::endl;
  else if (configuration == 3)
    std::cout << "3: \n\nDecrypt using key retriever that holds"
                 " the key of one encrypted column and the footer key. Pass aad_prefix."
              << std::endl;
  else if (configuration == 4)
    std::cout << "4: \n\nDecrypt using explicit column and footer keys. Pass aad_prefix."
              << std::endl;
  else {
    std::cout << "Unknown configuraion" << std::endl;
    exit(-1);
  }
  std::cout << std::endl;
}

void InteropTestwriteEncryptedParquetFiles(std::string rootPath) {

  /**********************************************************************************
                         Creating a number of Encryption configurations
   **********************************************************************************/

  // This vector will hold various encryption configuraions.
  std::vector<std::shared_ptr<parquet::FileEncryptionProperties>>
      vector_of_encryption_configurations;

  // Encryption configuration 1: Encrypt all columns and the footer with the same key.
  // (uniform encryption)
  parquet::FileEncryptionProperties::Builder file_encryption_builder_1(
      kFooterEncryptionKey);
  // Add to list of encryption configurations.
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_1.footer_key_metadata("kf")->build());

  // Encryption configuration 2: Encrypt two columns and the footer.
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols2;
  std::shared_ptr<parquet::schema::ColumnPath> path_ptr =
      parquet::schema::ColumnPath::FromDotString("double_field");
  std::shared_ptr<parquet::schema::ColumnPath> path_ptr1 =
      parquet::schema::ColumnPath::FromDotString("float_field");
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_20(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_21(path_ptr1);
  encryption_col_builder_20.key(kColumnEncryptionKey1)->key_id("kc1");
  encryption_col_builder_21.key(kColumnEncryptionKey2)->key_id("kc2");

  encryption_cols2[path_ptr] = encryption_col_builder_20.build();
  encryption_cols2[path_ptr1] = encryption_col_builder_21.build();

  parquet::FileEncryptionProperties::Builder file_encryption_builder_2(
      kFooterEncryptionKey);

  vector_of_encryption_configurations.push_back(
      file_encryption_builder_2.footer_key_metadata("kf")
          ->column_properties(encryption_cols2)
          ->build());

  // Encryption configuration 3: Encrypt two columns, don’t encrypt footer.
  // (plaintext footer mode, readable by legacy readers)
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols3;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_30(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_31(path_ptr1);
  encryption_col_builder_30.key(kColumnEncryptionKey1)->key_id("kc1");
  encryption_col_builder_31.key(kColumnEncryptionKey2)->key_id("kc2");

  encryption_cols3[path_ptr] = encryption_col_builder_30.build();
  encryption_cols3[path_ptr1] = encryption_col_builder_31.build();
  parquet::FileEncryptionProperties::Builder file_encryption_builder_3(
      kFooterEncryptionKey);

  vector_of_encryption_configurations.push_back(
      file_encryption_builder_3.footer_key_metadata("kf")
          ->column_properties(encryption_cols3)
          ->set_plaintext_footer()
          ->build());

  // Encryption configuration 4: Encrypt two columns and the footer. Use aad_prefix.
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols4;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_40(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_41(path_ptr1);
  encryption_col_builder_40.key(kColumnEncryptionKey1)->key_id("kc1");
  encryption_col_builder_41.key(kColumnEncryptionKey2)->key_id("kc2");

  encryption_cols4[path_ptr] = encryption_col_builder_40.build();
  encryption_cols4[path_ptr1] = encryption_col_builder_41.build();
  parquet::FileEncryptionProperties::Builder file_encryption_builder_4(
      kFooterEncryptionKey);

  vector_of_encryption_configurations.push_back(
      file_encryption_builder_4.footer_key_metadata("kf")
          ->column_properties(encryption_cols4)
          ->aad_prefix(fileName)
          ->build());

  // Encryption configuration 5: Encrypt two columns and the footer. Use aad_prefix and
  // disable_aad_prefix_storage.
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols5;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_50(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_51(path_ptr1);
  encryption_col_builder_50.key(kColumnEncryptionKey1)->key_id("kc1");
  encryption_col_builder_51.key(kColumnEncryptionKey2)->key_id("kc2");

  encryption_cols5[path_ptr] = encryption_col_builder_50.build();
  encryption_cols5[path_ptr1] = encryption_col_builder_51.build();
  parquet::FileEncryptionProperties::Builder file_encryption_builder_5(
      kFooterEncryptionKey);

  vector_of_encryption_configurations.push_back(
      file_encryption_builder_5.column_properties(encryption_cols5)
          ->footer_key_metadata("kf")
          ->aad_prefix(fileName)
          ->disable_store_aad_prefix_storage()
          ->build());

  // Encryption configuration 6: Encrypt two columns and the footer. Use AES_GCM_CTR_V1
  // algorithm.
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols6;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_60(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_61(path_ptr1);
  encryption_col_builder_60.key(kColumnEncryptionKey1)->key_id("kc1");
  encryption_col_builder_61.key(kColumnEncryptionKey2)->key_id("kc2");

  encryption_cols6[path_ptr] = encryption_col_builder_60.build();
  encryption_cols6[path_ptr1] = encryption_col_builder_61.build();
  parquet::FileEncryptionProperties::Builder file_encryption_builder_6(
      kFooterEncryptionKey);

  vector_of_encryption_configurations.push_back(
      file_encryption_builder_6.footer_key_metadata("kf")
          ->column_properties(encryption_cols6)
          ->algorithm(parquet::ParquetCipher::AES_GCM_CTR_V1)
          ->build());

  /**********************************************************************************
                                 PARQUET WRITER EXAMPLE
   **********************************************************************************/

  // Iterate over the encryption configurations and for each one write a parquet file.
  for (unsigned example_id = 0; example_id < vector_of_encryption_configurations.size();
       ++example_id) {
    std::stringstream ss;
    ss << example_id + 1;
    std::string test_number_string = ss.str();
    std::cout << "Write test " << test_number_string << std::endl;
    ;
    try {
      // Create a local file output stream instance.
      using FileClass = ::arrow::io::FileOutputStream;
      std::shared_ptr<FileClass> out_file;
      std::string file =
          rootPath + fileName + std::string(test_number_string) + ".parquet.encrypted";
      PARQUET_THROW_NOT_OK(FileClass::Open(file, &out_file));

      // Setup the parquet schema
      std::shared_ptr<GroupNode> schema = SetupSchema();

      // Add writer properties
      parquet::WriterProperties::Builder builder;
      builder.compression(parquet::Compression::SNAPPY);

      // Add the current encryption configuration to WriterProperties.
      builder.encryption(vector_of_encryption_configurations[example_id]);

      std::shared_ptr<parquet::WriterProperties> props = builder.build();

      // Create a ParquetFileWriter instance
      std::shared_ptr<parquet::ParquetFileWriter> file_writer =
          parquet::ParquetFileWriter::Open(out_file, schema, props);

      // Append a RowGroup with a specific number of rows.
      parquet::RowGroupWriter* rg_writer = file_writer->AppendRowGroup();

      // Write the Bool column
      parquet::BoolWriter* bool_writer =
          static_cast<parquet::BoolWriter*>(rg_writer->NextColumn());
      for (int i = 0; i < NUM_ROWS_PER_ROW_GROUP; i++) {
        bool value = ((i % 2) == 0) ? true : false;
        bool_writer->WriteBatch(1, nullptr, nullptr, &value);
      }

      // Write the Int32 column
      parquet::Int32Writer* int32_writer =
          static_cast<parquet::Int32Writer*>(rg_writer->NextColumn());
      for (int i = 0; i < NUM_ROWS_PER_ROW_GROUP; i++) {
        int32_t value = i;
        int32_writer->WriteBatch(1, nullptr, nullptr, &value);
      }

      // Write the Int64 column. Each row has repeats twice.
      parquet::Int64Writer* int64_writer =
          static_cast<parquet::Int64Writer*>(rg_writer->NextColumn());
      for (int i = 0; i < 2 * NUM_ROWS_PER_ROW_GROUP; i++) {
        int64_t value = i * 1000 * 1000;
        value *= 1000 * 1000;
        int16_t definition_level = 1;
        int16_t repetition_level = 0;
        if ((i % 2) == 0) {
          repetition_level = 1;  // start of a new record
        }
        int64_writer->WriteBatch(1, &definition_level, &repetition_level, &value);
      }

      // Write the INT96 column.
      parquet::Int96Writer* int96_writer =
          static_cast<parquet::Int96Writer*>(rg_writer->NextColumn());
      for (int i = 0; i < NUM_ROWS_PER_ROW_GROUP; i++) {
        parquet::Int96 value;
        value.value[0] = i;
        value.value[1] = i + 1;
        value.value[2] = i + 2;
        int96_writer->WriteBatch(1, nullptr, nullptr, &value);
      }

      // Write the Float column
      parquet::FloatWriter* float_writer =
          static_cast<parquet::FloatWriter*>(rg_writer->NextColumn());
      for (int i = 0; i < NUM_ROWS_PER_ROW_GROUP; i++) {
        float value = static_cast<float>(i) * 1.1f;
        float_writer->WriteBatch(1, nullptr, nullptr, &value);
      }

      // Write the Double column
      parquet::DoubleWriter* double_writer =
          static_cast<parquet::DoubleWriter*>(rg_writer->NextColumn());
      for (int i = 0; i < NUM_ROWS_PER_ROW_GROUP; i++) {
        double value = i * 1.1111111;
        double_writer->WriteBatch(1, nullptr, nullptr, &value);
      }

      // Write the ByteArray column. Make every alternate values NULL
      parquet::ByteArrayWriter* ba_writer =
          static_cast<parquet::ByteArrayWriter*>(rg_writer->NextColumn());
      for (int i = 0; i < NUM_ROWS_PER_ROW_GROUP; i++) {
        parquet::ByteArray value;
        char hello[FIXED_LENGTH] = "parquet";
        hello[7] = static_cast<char>(static_cast<int>('0') + i / 100);
        hello[8] = static_cast<char>(static_cast<int>('0') + (i / 10) % 10);
        hello[9] = static_cast<char>(static_cast<int>('0') + i % 10);
        if (i % 2 == 0) {
          int16_t definition_level = 1;
          value.ptr = reinterpret_cast<const uint8_t*>(&hello[0]);
          value.len = FIXED_LENGTH;
          ba_writer->WriteBatch(1, &definition_level, nullptr, &value);
        } else {
          int16_t definition_level = 0;
          ba_writer->WriteBatch(1, &definition_level, nullptr, nullptr);
        }
      }

      // Write the FixedLengthByteArray column
      parquet::FixedLenByteArrayWriter* flba_writer =
          static_cast<parquet::FixedLenByteArrayWriter*>(rg_writer->NextColumn());
      for (int i = 0; i < NUM_ROWS_PER_ROW_GROUP; i++) {
        parquet::FixedLenByteArray value;
        char v = static_cast<char>(i);
        char flba[FIXED_LENGTH] = {v, v, v, v, v, v, v, v, v, v};
        value.ptr = reinterpret_cast<const uint8_t*>(&flba[0]);

        flba_writer->WriteBatch(1, nullptr, nullptr, &value);
      }
      // Close the ParquetFileWriter
      std::cout << "file_writer->Close " << std::endl;
      file_writer->Close();

      // Write the bytes to file
      DCHECK(out_file->Close().ok());
    } catch (const std::exception& e) {
      std::cerr << "Parquet write error: " << e.what() << std::endl;
      return;
    }
  }
}

void InteropTestReadEncryptedParquetFiles(std::string rootPath) {
  std::vector<std::string> files_in_directory = GetDirectoryFiles(rootPath);

  /**********************************************************************************
                       Creating a number of Decryption configurations
   **********************************************************************************/

  // This vector will hold various decryption configurations.
  std::vector<std::shared_ptr<parquet::FileDecryptionProperties>>
      vector_of_decryption_configurations;

  // Decryption configuration 1: Decrypt using key retriever callback that holds the keys
  // of two encrypted columns and the footer key.

  std::shared_ptr<parquet::StringKeyIdRetriever> string_kr1 =
      std::make_shared<parquet::StringKeyIdRetriever>();
  string_kr1->PutKey("kf", kFooterEncryptionKey);
  string_kr1->PutKey("kc1", kColumnEncryptionKey1);
  string_kr1->PutKey("kc2", kColumnEncryptionKey2);
  std::shared_ptr<parquet::DecryptionKeyRetriever> kr1 =
      std::static_pointer_cast<parquet::StringKeyIdRetriever>(string_kr1);

  parquet::FileDecryptionProperties::Builder file_decryption_builder_1;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_1.key_retriever(kr1)->build());

  // Decryption configuration 2: Decrypt using key retriever callback that holds the keys
  // of two encrypted columns and the footer key. Supply aad_prefix.
  std::shared_ptr<parquet::StringKeyIdRetriever> string_kr2 =
      std::make_shared<parquet::StringKeyIdRetriever>();
  string_kr2->PutKey("kf", kFooterEncryptionKey);
  string_kr2->PutKey("kc1", kColumnEncryptionKey1);
  string_kr2->PutKey("kc2", kColumnEncryptionKey2);
  std::shared_ptr<parquet::DecryptionKeyRetriever> kr2 =
      std::static_pointer_cast<parquet::StringKeyIdRetriever>(string_kr2);

  parquet::FileDecryptionProperties::Builder file_decryption_builder_2;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_2.key_retriever(kr2)->aad_prefix(fileName)->build());

  // Decryption configuration 3: Decrypt using key retriever that holds the key of only
  // one encrypted column and the footer key. Supply aad_prefix.

  std::shared_ptr<parquet::StringKeyIdRetriever> string_kr_hidden_column =
      std::make_shared<parquet::StringKeyIdRetriever>();
  string_kr_hidden_column->PutKey("kf", kFooterEncryptionKey);
  string_kr_hidden_column->PutKey("kc1", kColumnEncryptionKey1);
  std::shared_ptr<parquet::DecryptionKeyRetriever> kr_hidden_column =
      std::static_pointer_cast<parquet::StringKeyIdRetriever>(string_kr_hidden_column);

  parquet::FileDecryptionProperties::Builder file_decryption_builder_3;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_3.key_retriever(kr_hidden_column)
          ->aad_prefix(fileName)
          ->build());

  // Decryption configuration 4: Decrypt using explicit column and footer keys. Supply
  // aad_prefix.
  std::shared_ptr<parquet::schema::ColumnPath> path_float_ptr =
      parquet::schema::ColumnPath::FromDotString("float_field");
  std::shared_ptr<parquet::schema::ColumnPath> path_double_ptr =
      parquet::schema::ColumnPath::FromDotString("double_field");
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnDecryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      decryption_cols;
  parquet::ColumnDecryptionProperties::Builder decryption_col_builder41(path_double_ptr);
  parquet::ColumnDecryptionProperties::Builder decryption_col_builder42(path_float_ptr);

  decryption_cols[path_double_ptr] =
      decryption_col_builder41.key(kColumnEncryptionKey1)->build();
  decryption_cols[path_float_ptr] =
      decryption_col_builder42.key(kColumnEncryptionKey2)->build();

  parquet::FileDecryptionProperties::Builder file_decryption_builder_4;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_4.footer_key(kFooterEncryptionKey)
          ->aad_prefix(fileName)
          ->column_properties(decryption_cols)
          ->build());

  /**********************************************************************************
                             PARQUET READER EXAMPLE
  **********************************************************************************/

  // Iterate over the decryption configurations and use each one to read every files
  // in the input directory.
  for (unsigned example_id = 0; example_id < vector_of_decryption_configurations.size();
       ++example_id) {
    PrintDecryptionConfiguration(example_id + 1);
    for (auto const& file : files_in_directory) {
      if (file.find("parquet.encrypted") ==
          std::string::npos)  // Skip non encrypted files
        continue;
      try {
        std::cout << "--> Read file " << file << std::endl;

        parquet::ReaderProperties reader_properties =
            parquet::default_reader_properties();

        // Add the current decryption configuration to ReaderProperties.
        reader_properties.file_decryption_properties(
            vector_of_decryption_configurations[example_id]);

        // Create a ParquetReader instance
        std::unique_ptr<parquet::ParquetFileReader> parquet_reader =
            parquet::ParquetFileReader::OpenFile(rootPath + file, false,
                                                 reader_properties);

        // Get the File MetaData
        std::shared_ptr<parquet::FileMetaData> file_metadata = parquet_reader->metadata();

        // Get the number of RowGroups
        int num_row_groups = file_metadata->num_row_groups();
        assert(num_row_groups == 1);

        // Get the number of Columns
        int num_columns = file_metadata->num_columns();
        assert(num_columns == 8);

        // Iterate over all the RowGroups in the file
        for (int r = 0; r < num_row_groups; ++r) {
          // Get the RowGroup Reader
          std::shared_ptr<parquet::RowGroupReader> row_group_reader =
              parquet_reader->RowGroup(r);

          int64_t values_read = 0;
          int64_t rows_read = 0;
          int16_t definition_level;
          int16_t repetition_level;
          int i;
          std::shared_ptr<parquet::ColumnReader> column_reader;

          // Get the Column Reader for the boolean column
          column_reader = row_group_reader->Column(0);
          parquet::BoolReader* bool_reader =
              static_cast<parquet::BoolReader*>(column_reader.get());

          // Read all the rows in the column
          i = 0;
          while (bool_reader->HasNext()) {
            bool value;
            // Read one value at a time. The number of rows read is returned. values_read
            // contains the number of non-null rows
            rows_read = bool_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
            // Ensure only one value is read
            assert(rows_read == 1);
            // There are no NULL values in the rows written
            assert(values_read == 1);
            // Verify the value written
            bool expected_value = ((i % 2) == 0) ? true : false;
            assert(value == expected_value);
            i++;
          }

          // Get the Column Reader for the Int32 column
          column_reader = row_group_reader->Column(1);
          parquet::Int32Reader* int32_reader =
              static_cast<parquet::Int32Reader*>(column_reader.get());
          // Read all the rows in the column
          i = 0;
          while (int32_reader->HasNext()) {
            int32_t value;
            // Read one value at a time. The number of rows read is returned. values_read
            // contains the number of non-null rows
            rows_read =
                int32_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
            // Ensure only one value is read
            assert(rows_read == 1);
            // There are no NULL values in the rows written
            assert(values_read == 1);
            // Verify the value written
            assert(value == i);
            i++;
          }

          // Get the Column Reader for the Int64 column
          column_reader = row_group_reader->Column(2);
          parquet::Int64Reader* int64_reader =
              static_cast<parquet::Int64Reader*>(column_reader.get());
          // Read all the rows in the column
          i = 0;
          while (int64_reader->HasNext()) {
            int64_t value;
            // Read one value at a time. The number of rows read is returned. values_read
            // contains the number of non-null rows
            rows_read = int64_reader->ReadBatch(1, &definition_level, &repetition_level,
                                                &value, &values_read);
            // Ensure only one value is read
            assert(rows_read == 1);
            // There are no NULL values in the rows written
            assert(values_read == 1);
            // Verify the value written
            int64_t expected_value = i * 1000 * 1000;
            expected_value *= 1000 * 1000;
            assert(value == expected_value);
            if ((i % 2) == 0) {
              assert(repetition_level == 1);
            } else {
              assert(repetition_level == 0);
            }
            i++;
          }

          // Get the Column Reader for the Int96 column
          column_reader = row_group_reader->Column(3);
          parquet::Int96Reader* int96_reader =
              static_cast<parquet::Int96Reader*>(column_reader.get());
          // Read all the rows in the column
          i = 0;
          while (int96_reader->HasNext()) {
            parquet::Int96 value;
            // Read one value at a time. The number of rows read is returned. values_read
            // contains the number of non-null rows
            rows_read =
                int96_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
            // Ensure only one value is read
            assert(rows_read == 1);
            // There are no NULL values in the rows written
            assert(values_read == 1);
            // Verify the value written
            parquet::Int96 expected_value;
            expected_value.value[0] = i;
            expected_value.value[1] = i + 1;
            expected_value.value[2] = i + 2;
            for (int j = 0; j < 3; j++) {
              assert(value.value[j] == expected_value.value[j]);
            }
            i++;
          }

          // Get the Column Reader for the Float column
          column_reader = row_group_reader->Column(4);
          parquet::FloatReader* float_reader =
              static_cast<parquet::FloatReader*>(column_reader.get());
          // Read all the rows in the column
          i = 0;
          while (float_reader->HasNext()) {
            float value;
            // Read one value at a time. The number of rows read is returned. values_read
            // contains the number of non-null rows
            rows_read =
                float_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
            // Ensure only one value is read
            assert(rows_read == 1);
            // There are no NULL values in the rows written
            assert(values_read == 1);
            // Verify the value written
            float expected_value = static_cast<float>(i) * 1.1f;
            assert(value == expected_value);
            i++;
          }

          // Get the Column Reader for the Double column
          column_reader = row_group_reader->Column(5);
          parquet::DoubleReader* double_reader =
              static_cast<parquet::DoubleReader*>(column_reader.get());
          // Read all the rows in the column
          i = 0;
          while (double_reader->HasNext()) {
            double value;
            // Read one value at a time. The number of rows read is returned. values_read
            // contains the number of non-null rows
            rows_read =
                double_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
            // Ensure only one value is read
            assert(rows_read == 1);
            // There are no NULL values in the rows written
            assert(values_read == 1);
            // Verify the value written
            double expected_value = i * 1.1111111;
            assert(value == expected_value);
            i++;
          }

          // Get the Column Reader for the ByteArray column
          column_reader = row_group_reader->Column(6);
          parquet::ByteArrayReader* ba_reader =
              static_cast<parquet::ByteArrayReader*>(column_reader.get());
          // Read all the rows in the column
          i = 0;
          while (ba_reader->HasNext()) {
            parquet::ByteArray value;
            // Read one value at a time. The number of rows read is returned. values_read
            // contains the number of non-null rows
            rows_read =
                ba_reader->ReadBatch(1, &definition_level, nullptr, &value, &values_read);
            // Ensure only one value is read
            assert(rows_read == 1);
            // Verify the value written
            char expected_value[FIXED_LENGTH] = "parquet";
            expected_value[7] = static_cast<char>('0' + i / 100);
            expected_value[8] = static_cast<char>('0' + (i / 10) % 10);
            expected_value[9] = static_cast<char>('0' + i % 10);
            if (i % 2 == 0) {  // only alternate values exist
              // There are no NULL values in the rows written
              assert(values_read == 1);
              assert(value.len == FIXED_LENGTH);
              assert(memcmp(value.ptr, &expected_value[0], FIXED_LENGTH) == 0);
              assert(definition_level == 1);
            } else {
              // There are NULL values in the rows written
              assert(values_read == 0);
              assert(definition_level == 0);
            }
            i++;
          }

          // Get the Column Reader for the FixedLengthByteArray column
          column_reader = row_group_reader->Column(7);
          parquet::FixedLenByteArrayReader* flba_reader =
              static_cast<parquet::FixedLenByteArrayReader*>(column_reader.get());
          // Read all the rows in the column
          i = 0;
          while (flba_reader->HasNext()) {
            parquet::FixedLenByteArray value;
            // Read one value at a time. The number of rows read is returned. values_read
            // contains the number of non-null rows
            rows_read = flba_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
            // Ensure only one value is read
            assert(rows_read == 1);
            // There are no NULL values in the rows written
            assert(values_read == 1);
            // Verify the value written
            char v = static_cast<char>(i);
            char expected_value[FIXED_LENGTH] = {v, v, v, v, v, v, v, v, v, v};
            assert(memcmp(value.ptr, &expected_value[0], FIXED_LENGTH) == 0);
            i++;
          }
        }
      } catch (const std::exception& e) {
        std::cerr << "Parquet read error: " << e.what() << std::endl;
      }
      std::cout << "file [" << file << "] Parquet Reading Complete" << std::endl;
    }
  }
}

int main(int argc, char** argv) {
  enum Operation { write, read };
  std::string rootPath;
  Operation operation = write;
  if (argc < 3) {
    std::cout << "Usage: encryption-doInterop-tests <read/write> <Path-to-parquet-files>"
              << std::endl;
    exit(1);
  }
  rootPath = argv[1];
  if (rootPath.compare("read") == 0) {
    operation = read;
  }

  rootPath = argv[2];
  std::cout << "Root path is: " << rootPath << std::endl;

  if (operation == write) {
    InteropTestwriteEncryptedParquetFiles(rootPath);
  } else
    InteropTestReadEncryptedParquetFiles(rootPath);

  return 0;
}