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

#include <cassert>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

#include <arrow/io/file.h>
#include <arrow/util/logging.h>

#include <parquet/api/reader.h>

/*
 * This example contains tests for reading Parquet Files in C++ with encrypted columns
 * to be used for iterop testing.
 *
 * A detailed description of the Parquet Modular Encryption specification can be found
 * here:
 * https://github.com/apache/parquet-format/blob/encryption/Encryption.md
 *
 * The example contains reading four columns with the following different encryption
 * configurations:
 *  - Test 1:   Decrypt two encrypted columns and encrypted footer. The encryption was
 *              done using parquet-cpp.
 *  - Test 2:   Decrypt two columns and the footer. The encryption was done using parquet-mr.
 *  - Test 3:   Decrypt parquet file with two encrypted columns and encrypted footer. 
 *              The decryption is done without providing key for one column. 
 *              The encryption was done using parquet-cpp.
 *  - Test 4:   Decrypt parquet file with two encrypted columns and encrypted footer. 
 *              The decryption is done without providing key for one column. 
 *              The encryption was done using parquet-mr.
 *  - Test 6 -  Decrypt two encrypted columns and encrypted footer. 
 *              The encryption was done using parquet-cpp with aad_prefix.
 *  - Test 7 -  Decrypt two encrypted columns and encrypted footer. 
 *              The encryption was done using parquet-mr with aad_prefix.
 *  - Test 8 -  Decrypt two encrypted columns and encrypted footer. 
 *              The encryption was *done using parquet-cpp
 *              with aad_prefix and disable_store_aad_prefix_storage.
 *  - Test 10 - Decrypt two encrypted columns and encrypted footer. 
 *              The encryption was done using parquet-cpp with_GCM_CTR_V1 algorithm.
 * 
 *  The path to a directory which the parquet files should be read from can be 
 *  passed as a parameter.
 **/

constexpr int NUM_ROWS_PER_ROW_GROUP = 500;

const std::string FOOTER_ENCRYPTION_KEY = "0123456789012345";   // 16 bytes
const std::string COLUMN_ENCRYPTION_KEY1 = "1234567890123450";  // 16 bytes
const std::string COLUMN_ENCRYPTION_KEY2 = "1234567890123451";  // 16 bytes
const std::string fileName = "tester";

int main(int argc, char** argv) {
  std::string root;
  if (argc > 1) {
    root = argv[1];
    std::cout << "Root path is: " << root << std::endl;
  }

  int numTests = 0;
  int testsNumber[10];
  std::shared_ptr<parquet::StringKeyIdRetriever> string_kr =
      std::make_shared<parquet::StringKeyIdRetriever>();
  string_kr->PutKey("kf", FOOTER_ENCRYPTION_KEY);
  string_kr->PutKey("kc1", COLUMN_ENCRYPTION_KEY1);
  string_kr->PutKey("kc2", COLUMN_ENCRYPTION_KEY2);
  std::shared_ptr<parquet::DecryptionKeyRetriever> kr =
      std::static_pointer_cast<parquet::StringKeyIdRetriever>(string_kr);

  std::vector<std::shared_ptr<parquet::FileDecryptionProperties>>
      vector_of_decryption_configurations;

  // Test #1 - Decrypt two columns and the footer. The parquet file was genrated using
  // parquet-cpp
  testsNumber[numTests++] = 1;

  parquet::FileDecryptionProperties::Builder file_decryption_builder_1;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_1.key_retriever(kr)->build());

  // Test #2 - Decrypt two columns and the footer. The parquet file was genrated using
  // parquet-mr
  testsNumber[numTests++] = 2;

  parquet::FileDecryptionProperties::Builder file_decryption_builder_2;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_2.key_retriever(kr)->build());

  std::shared_ptr<parquet::StringKeyIdRetriever> string_kr_hidden_column =
      std::make_shared<parquet::StringKeyIdRetriever>();
  string_kr_hidden_column->PutKey("kf", FOOTER_ENCRYPTION_KEY);
  string_kr_hidden_column->PutKey("kc1", COLUMN_ENCRYPTION_KEY1);
  std::shared_ptr<parquet::DecryptionKeyRetriever> kr_hidden_column =
      std::static_pointer_cast<parquet::StringKeyIdRetriever>(string_kr_hidden_column);
  // Test #3 - Decrypt two columns and the footer. The parquet file was genrated using
  // parquet-cpp
  testsNumber[numTests++] = 3;
  parquet::FileDecryptionProperties::Builder file_decryption_builder_3;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_3.key_retriever(kr_hidden_column)->build());

  // Test #4 - Decrypt two columns and the footer. The parquet file was genrated using
  // parquet-mr
  testsNumber[numTests++] = 4;

  parquet::FileDecryptionProperties::Builder file_decryption_builder_4;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_4.key_retriever(kr_hidden_column)->build());

  // Test #6 - Decrypt two columns and the footer. The parquet file was genrated using
  // parquet-cpp with AADprefix
  testsNumber[numTests++] = 6;
  parquet::FileDecryptionProperties::Builder file_decryption_builder_6;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_6.key_retriever(kr)->build());

  // Test #7 - Decrypt two columns and the footer. The parquet file was genrated using
  // parquet-mr with AADprefix
  testsNumber[numTests++] = 7;
  parquet::FileDecryptionProperties::Builder file_decryption_builder_7;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_7.key_retriever(kr)->build());

  // Test #8 - Decrypt two columns and the footer. The parquet file was genrated using
  // parquet-cpp with AADprefix and disable_store_aad_prefix_storage
  testsNumber[numTests++] = 8;
  parquet::FileDecryptionProperties::Builder file_decryption_builder_8;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_8.key_retriever(kr)->aad_prefix(fileName)->build());

  // Test #10 - Decrypt two columns and the footer. The parquet file was genrated using
  // parquet-cpp with gcm_ctr algotithm
  testsNumber[numTests++] = 10;
  parquet::FileDecryptionProperties::Builder file_decryption_builder_10;
  vector_of_decryption_configurations.push_back(
      file_decryption_builder_10.key_retriever(kr)->build());

  /**********************************************************************************
                             PARQUET READER EXAMPLE
  **********************************************************************************/
  for (unsigned example_id = 0; example_id < vector_of_decryption_configurations.size();
       ++example_id) {
    try {
      std::stringstream ss;
      ss << testsNumber[example_id];
      std::string test_number_string = ss.str();
      std::cout << "--> Read test " << test_number_string << std::endl;
      ;
      parquet::ReaderProperties reader_properties = parquet::default_reader_properties();

      // Add the current decryption configuration to ReaderProperties.
      reader_properties.file_decryption_properties(
          vector_of_decryption_configurations[example_id]);
      std::string file =
          root + fileName + std::string(test_number_string) + ".parquet.encrypted";
      std::cout << file << std::endl;
      ;

      // Create a ParquetReader instance
      std::unique_ptr<parquet::ParquetFileReader> parquet_reader =
          parquet::ParquetFileReader::OpenFile(file, false, reader_properties);

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
          rows_read = int32_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
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
          rows_read = float_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
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
          rows_read = double_reader->ReadBatch(1, nullptr, nullptr, &value, &values_read);
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
    std::cout << "Example [" << (example_id + 1) << "] Parquet Reading Complete"
              << std::endl;
  }
  return 0;
}
