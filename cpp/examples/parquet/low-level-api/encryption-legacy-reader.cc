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

#include <arrow/io/file.h>
#include <arrow/util/logging.h>

#include <parquet/api/reader.h>
#include <parquet/api/writer.h>

/*
 * This example contains a test reading for encrypted Parquet file using 
 * parquet-cpp version that does not support encryption.
 * Its purpose it to test the ability of legacy parquet-cpp to read encrypted 
 * parquet file as part of the legacy code check.
 * In this test two non encrypted columns are read. The parquet file contains four 
 * columns where two of them and the footer were encrypted using parquet-cpp version
 * that supports encryption.
 *
 * A detailed description of the Parquet Modular Encryption specification can be found
 * here:
 * https://github.com/apache/parquet-format/blob/encryption/Encryption.md
 *
 */

constexpr int NUM_ROWS_PER_ROW_GROUP = 500;

int main(int argc, char** argv) {
  std::string encrypted_parquet_file;
  if (argc > 1) {
    encrypted_parquet_file = argv[1];
    std::cout << "encrypted parquet file is: " << encrypted_parquet_file << std::endl;
  }

  /**********************************************************************************
                             PARQUET READER EXAMPLE
  **********************************************************************************/

  try {
    // Create a ParquetReader instance
    std::unique_ptr<parquet::ParquetFileReader> parquet_reader =
        parquet::ParquetFileReader::OpenFile(encrypted_parquet_file, false);

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
      std::cout << "bool_reader " << i << std::endl;
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
      std::cout << "int32_reader " << i << std::endl;
    }
  } catch (const std::exception& e) {
    std::cerr << "Parquet read error: " << e.what() << std::endl;
    return -1;
  }

  std::cout << "Parquet Reading Complete" << std::endl;

  return 0;
}
