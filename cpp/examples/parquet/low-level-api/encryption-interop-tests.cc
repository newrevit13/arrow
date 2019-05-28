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

#include <encryption_interop_tests.h>

/*
 * This example contains tests for writing and reading encrypted parquet Files
 * to be used for iterop testing.
 *
 * This tests use encryption configurations that cover the basic encryption modes.
 * More configurations are excpeted to be added.
 *
 * The write tests produce number of encrypted parquet files that can be read by java
 * parquet-mr version which supports encryption. Each file is encrypted with different
 * encryption configuration as described below. The name of each parquet file produced
 * is in the form of tester<test number>.parquet.encrypted. For example, for test number
 * 1 tester1.parquet.encrypted file will be generated.
 *
 * To read the encrypted parquet files produced by java parquet-mr version several
 * encryption configurations are applied on all the encrypted files.
 * The different encryption configurations are listed below.
 *
 * Usage: ./encrytion-interop-tests <write/read> <path-to-directory-of-parquet-files>
 *
 * A detailed description of the Parquet Modular Encryption specification can be found
 * here:
 * https://github.com/apache/parquet-format/blob/encryption/Encryption.md
 *
 * The write tests contain writing four columns with the following different encryption
 * configurations:
 *  - Test 1:   Encrypt all columns and the footer with the same key. (uniform
 *              encryption)
 *  - Test 2:   Encrypt two columns and the footer.
 *  - Test 3:   Encrypt two columns and footer. Use plaintext footer mode.
 *  - Test 4 -  Encrypt two columns and the footer. Use aad_prefix.
 *  - Test 5 -  Encrypt two columns and the footer. Use aad_prefix and
 *              disable_aad_prefix_storage.
 *  - Test 6 - Encrypt two columns and the footer. Use AES_GCM_CTR_V1 algorithm.
 *
 * The read tests use the following decryption configurations to read all encrypted
 * files in input directory:
 *  - Decryption configuration 1: Decrypt using key retriever that holds the keys of two
 *                                encrypted columns and the footer key.
 *  - Decryption configuration 2: Decrypt using key retriever that holds the keys of two
 *                                encrypted columns and the footer key. Pass aad_prefix.
 *  - Decryption configuration 3: Decrypt using key retriever that holds the key of one
 *                                encrypted column and the footer key. Pass aad_prefix.
 *  - Decryption configuration 4: Decrypt using column decryption properties. Pass
 *                                aad_prefix.
 **/

constexpr int NUM_ROWS_PER_ROW_GROUP = 500;

const std::string kFooterEncryptionKey = "0123456789012345";   // 16 bytes
const std::string kColumnEncryptionKey1 = "1234567890123450";  // 16 bytes
const std::string kColumnEncryptionKey2 = "1234567890123451";  // 16 bytes
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

void PrintEncryptionConfiguration(int configuration) {
  if (configuration == 1)
    std::cout << "Decryption configuration 1: Decrypt using key retriever that holds the "
                 "keys of two encrypted columns and the footer key."
              << std::endl;
  else if (configuration == 2)
    std::cout << "Decryption configuration 2: Decrypt using key retriever that holds the "
                 "keys of two encrypted columns and the footer key. Pass aad_prefix."
              << std::endl;
  else if (configuration == 3)
    std::cout << "Decryption configuration 3: Decrypt using key retriever that holds the "
                 "key of one encrypted column and the footer key. Pass aad_prefix."
              << std::endl;
  else if (configuration == 4)
    std::cout << "Decryption configuration 4: Decrypt using column decryption "
                 "properties. Pass aad_prefix."
              << std::endl;
  else
    std::cout << "Unknown configuraion" << std::endl;
}

void InteropReadTests(std::string rootPath) {
  std::vector<std::string> files_in_directory = GetDirectoryFiles(rootPath);
  // Decryption configuration 1: Decrypt using key retriever that holds the keys of two
  //                                encrypted columns and the footer key.

  std::shared_ptr<parquet::StringKeyIdRetriever> string_kr =
      std::make_shared<parquet::StringKeyIdRetriever>();
  string_kr->PutKey("kf", kFooterEncryptionKey);
  string_kr->PutKey("kc1", kColumnEncryptionKey1);
  string_kr->PutKey("kc2", kColumnEncryptionKey2);
  std::shared_ptr<parquet::DecryptionKeyRetriever> kr =
      std::static_pointer_cast<parquet::StringKeyIdRetriever>(string_kr);

  std::vector<std::shared_ptr<parquet::FileDecryptionProperties>>
      vector_of_decryption_configurations;

  parquet::FileDecryptionProperties::Builder file_decryption_builder_1;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_1.key_retriever(kr)->build());

  // Decryption configuration 2: Decrypt using key retriever that holds the keys of two
  //                                encrypted columns and the footer key. Pass aad_prefix.
  parquet::FileDecryptionProperties::Builder file_decryption_builder_2;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_2.key_retriever(kr)->aad_prefix(fileName)->build());

  // Decryption configuration 3: Decrypt using key retriever that holds the key of one
  //                                encrypted column and the footer key. Pass aad_prefix.

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

  //  - Decryption configuration 4: Decrypt using column decryption properties. Pass
  //                                aad_prefix.

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
  for (unsigned example_id = 0; example_id < vector_of_decryption_configurations.size();
       ++example_id) {
    for (auto const& file : files_in_directory) {
      if (file.find("parquet.encrypted") == std::string::npos)  // Skip non parquet files
        continue;
      try {
        std::cout << "--> Read file " << file << " " << std::endl;
        PrintEncryptionConfiguration(example_id + 1);

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
        assert(num_columns == 4);

        // Iterate over all the RowGroups in the file
        for (int r = 0; r < num_row_groups; ++r) {
          // Get the RowGroup Reader
          std::shared_ptr<parquet::RowGroupReader> row_group_reader =
              parquet_reader->RowGroup(r);

          int64_t values_read = 0;
          int64_t rows_read = 0;
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

          // Get the Column Reader for the Float column
          column_reader = row_group_reader->Column(2);
          parquet::FloatReader* float_reader =
              static_cast<parquet::FloatReader*>(column_reader.get());

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
          column_reader = row_group_reader->Column(3);
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
        }
      } catch (const std::exception& e) {
        std::cerr << "Parquet read error: " << e.what() << std::endl;
      }
      std::cout << "file [" << file << "] Parquet Reading Complete" << std::endl;
    }
  }
}

void InteropWriteTests(std::string rootPath) {
  std::vector<std::shared_ptr<parquet::FileEncryptionProperties>>
      vector_of_encryption_configurations;
  int testsNumber[10];
  int numTests = 0;

  // Test #1 - Encrypt all columns and the footer with the same key. (uniform encryption)
  testsNumber[numTests++] = 1;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_1(
      kFooterEncryptionKey);
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_1.footer_key_metadata("kf")->build());

  // Test #2 - Encrypt two columns and the footer
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

  testsNumber[numTests++] = 2;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_2(
      kFooterEncryptionKey);
  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_2.footer_key_metadata("kf")
          ->column_properties(encryption_cols2)
          ->build());

  // Test #3 - Encrypt two columns and footer. Use plaintext footer mode
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
  testsNumber[numTests++] = 3;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_3(
      kFooterEncryptionKey);

  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_3.footer_key_metadata("kf")
          ->column_properties(encryption_cols3)
          ->set_plaintext_footer()
          ->build());

  // Test #4 - Encrypt two columns and the footer. Use aad_prefix.
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
  testsNumber[numTests++] = 4;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_4(
      kFooterEncryptionKey);

  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_4.footer_key_metadata("kf")
          ->column_properties(encryption_cols4)
          ->aad_prefix(fileName)
          ->build());

  // Test #5 - Encrypt two columns and the footer. Use aad_prefix and
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
  testsNumber[numTests++] = 5;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_5(
      kFooterEncryptionKey);

  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_5.column_properties(encryption_cols5)
          ->footer_key_metadata("kf")
          ->aad_prefix(fileName)
          ->disable_store_aad_prefix_storage()
          ->build());

  // Test #6 - Encrypt two columns and the footer. Use AES_GCM_CTR_V1 algorithm.
  testsNumber[numTests++] = 6;
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

  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_6.footer_key_metadata("kf")
          ->column_properties(encryption_cols6)
          ->algorithm(parquet::ParquetCipher::AES_GCM_CTR_V1)
          ->build());

  std::shared_ptr<parquet::StringKeyIdRetriever> string_kr =
      std::make_shared<parquet::StringKeyIdRetriever>();
  string_kr->PutKey("kf", kFooterEncryptionKey);
  string_kr->PutKey("kc1", kColumnEncryptionKey1);
  string_kr->PutKey("kc2", kColumnEncryptionKey2);
  std::shared_ptr<parquet::DecryptionKeyRetriever> kr =
      std::static_pointer_cast<parquet::StringKeyIdRetriever>(string_kr);

  parquet::FileDecryptionProperties::Builder decryption_properties_builder_0;
  decryption_properties_builder_0.key_retriever(kr);
  for (unsigned example_id = 0; example_id < vector_of_encryption_configurations.size();
       ++example_id) {
    /**********************************************************************************
                               PARQUET WRITER EXAMPLE
    **********************************************************************************/
    std::stringstream ss;
    ss << testsNumber[example_id];
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
    InteropWriteTests(rootPath);
  } else
    InteropReadTests(rootPath);

  return 0;
}
