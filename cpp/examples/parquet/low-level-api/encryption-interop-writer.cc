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

#include <encryption_interop_tests.h>

/*
 * This example contains tests for writing Parquet Files in C++ with encrypted columns
 * to be used for iterop testing.
 *
 * A detailed description of the Parquet Modular Encryption specification can be found
 * here:
 * https://github.com/apache/parquet-format/blob/encryption/Encryption.md
 *
 * The example contains writing four columns with the following different encryption
 * configurations:
 *  - Test 1:   Encrypt two columns and the footer.
 *  - Test 3:   Encrypt two columns and footer. The decryption is done
 *              without providing key for one column.
 *  - Test 5:   Encrypt two columns and footer. Use plaintext footer mode.
 *  - Test 6 -  Encrypt two columns and the footer. Use aad_prefix.
 *  - Test 8 -  Encrypt two columns and the footer. Use aad_prefix and
 *              disable_store_aad_prefix_storage.
 *  - Test 10 - Encrypt two columns and the footer. Use AES_GCM_CTR_V1 algorithm.
 * 
 *  The path to a directory which the parquet files should be written to can be
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

  std::vector<std::shared_ptr<parquet::FileEncryptionProperties>>
      vector_of_encryption_configurations;
  int testsNumber[10];

  // Test #1 - encrypt two columns and the footer
  int numTests = 0;

  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols1;
  std::shared_ptr<parquet::schema::ColumnPath> path_ptr =
      parquet::schema::ColumnPath::FromDotString("double_field");
  std::shared_ptr<parquet::schema::ColumnPath> path_ptr1 =
      parquet::schema::ColumnPath::FromDotString("float_field");
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_10(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_11(path_ptr1);
  encryption_col_builder_10.key(COLUMN_ENCRYPTION_KEY1)->key_id("kc1");
  encryption_col_builder_11.key(COLUMN_ENCRYPTION_KEY2)->key_id("kc2");

  encryption_cols1[path_ptr] = encryption_col_builder_10.build();
  encryption_cols1[path_ptr1] = encryption_col_builder_11.build();

  std::string footerKeyName = "kf";

  testsNumber[numTests++] = 1;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_0(
      FOOTER_ENCRYPTION_KEY);
  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_0.footer_key_metadata(footerKeyName)
          ->column_properties(encryption_cols1)
          ->build());

  // Test #3 - encrypt two columns and the footer. Decrypt without providing key for one
  // column
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols3;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_30(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_31(path_ptr1);
  encryption_col_builder_30.key(COLUMN_ENCRYPTION_KEY1)->key_id("kc1");
  encryption_col_builder_31.key(COLUMN_ENCRYPTION_KEY2)->key_id("kc2");

  encryption_cols3[path_ptr] = encryption_col_builder_30.build();
  encryption_cols3[path_ptr1] = encryption_col_builder_31.build();
  testsNumber[numTests++] = 3;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_3(
      FOOTER_ENCRYPTION_KEY);
  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_3.footer_key_metadata(footerKeyName)
          ->column_properties(encryption_cols3)
          ->build());
  // Test #5 - encrypt two columns and the footer. Use plaintext footer mode.
    std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols5;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_50(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_51(path_ptr1);
  encryption_col_builder_50.key(COLUMN_ENCRYPTION_KEY1)->key_id("kc1");
  encryption_col_builder_51.key(COLUMN_ENCRYPTION_KEY2)->key_id("kc2");

  encryption_cols5[path_ptr] = encryption_col_builder_50.build();
  encryption_cols5[path_ptr1] = encryption_col_builder_51.build();
  testsNumber[numTests++] = 5;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_5(
      FOOTER_ENCRYPTION_KEY);

  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_5.footer_key_metadata(footerKeyName)
          ->column_properties(encryption_cols5)
          ->set_plaintext_footer()
          ->build());

  // Test #6 - encrypt two columns and the footer. Use aad_prefix.
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols6;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_60(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_61(path_ptr1);
  encryption_col_builder_60.key(COLUMN_ENCRYPTION_KEY1)->key_id("kc1");
  encryption_col_builder_61.key(COLUMN_ENCRYPTION_KEY2)->key_id("kc2");

  encryption_cols6[path_ptr] = encryption_col_builder_60.build();
  encryption_cols6[path_ptr1] = encryption_col_builder_61.build();
  testsNumber[numTests++] = 6;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_6(
      FOOTER_ENCRYPTION_KEY);

  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_6.footer_key_metadata(footerKeyName)
          ->column_properties(encryption_cols6)
          ->aad_prefix(fileName)
          ->build());

  // Test #8 - encrypt two columns and the footer. Use aad_prefix and
  // disable_store_aad_prefix_storage.
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols8;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_80(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_81(path_ptr1);
  encryption_col_builder_80.key(COLUMN_ENCRYPTION_KEY1)->key_id("kc1");
  encryption_col_builder_81.key(COLUMN_ENCRYPTION_KEY2)->key_id("kc2");

  encryption_cols8[path_ptr] = encryption_col_builder_80.build();
  encryption_cols8[path_ptr1] = encryption_col_builder_81.build();
  testsNumber[numTests++] = 8;
  parquet::FileEncryptionProperties::Builder file_encryption_builder_8(
      FOOTER_ENCRYPTION_KEY);

  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_8.column_properties(encryption_cols8)
          ->footer_key_metadata(footerKeyName)
          ->aad_prefix(fileName)
          ->disable_store_aad_prefix_storage()
          ->build());

  // Test #10 - encrypt two columns and the footer. Use AES_GCM_CTR_V1 algorithm.
  testsNumber[numTests++] = 10;
  std::map<std::shared_ptr<parquet::schema::ColumnPath>,
           std::shared_ptr<parquet::ColumnEncryptionProperties>,
           parquet::schema::ColumnPath::CmpColumnPath>
      encryption_cols10;
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_100(path_ptr);
  parquet::ColumnEncryptionProperties::Builder encryption_col_builder_101(path_ptr1);
  encryption_col_builder_100.key(COLUMN_ENCRYPTION_KEY1)->key_id("kc1");
  encryption_col_builder_101.key(COLUMN_ENCRYPTION_KEY2)->key_id("kc2");

  encryption_cols10[path_ptr] = encryption_col_builder_100.build();
  encryption_cols10[path_ptr1] = encryption_col_builder_101.build();
  parquet::FileEncryptionProperties::Builder file_encryption_builder_10(
      FOOTER_ENCRYPTION_KEY);

  // Add the properties to the appropriate configurations vectors
  vector_of_encryption_configurations.push_back(
      file_encryption_builder_10.footer_key_metadata(footerKeyName)
          ->column_properties(encryption_cols10)
          ->algorithm(parquet::ParquetCipher::AES_GCM_CTR_V1)
          ->build());

  std::shared_ptr<parquet::StringKeyIdRetriever> string_kr =
      std::make_shared<parquet::StringKeyIdRetriever>();
  string_kr->PutKey("kf", FOOTER_ENCRYPTION_KEY);
  string_kr->PutKey("kc1", COLUMN_ENCRYPTION_KEY1);
  string_kr->PutKey("kc2", COLUMN_ENCRYPTION_KEY2);
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
          root + fileName + std::string(test_number_string) + ".parquet.encrypted";
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
      return -1;
    }
  }

  return 0;
}
