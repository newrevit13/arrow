# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

add_executable(parquet-low-level-example low-level-api/reader-writer.cc)
add_executable(parquet-low-level-example2 low-level-api/reader-writer2.cc)
add_executable(parquet-encryption-example low-level-api/encryption-reader-writer.cc)
add_executable(parquet-encryption-interop-writer low-level-api/encryption-interop-writer.cc)
add_executable(parquet-encryption-interop-reader low-level-api/encryption-interop-reader.cc)
add_executable(parquet-encryption-legacy-reader low-level-api/encryption-legacy-reader.cc)
target_include_directories(parquet-low-level-example PRIVATE low-level-api/)
target_include_directories(parquet-low-level-example2 PRIVATE low-level-api/)
target_include_directories(parquet-encryption-example PRIVATE low-level-api/)
target_include_directories(parquet-encryption-interop-writer PRIVATE low-level-api/)
target_include_directories(parquet-encryption-interop-reader PRIVATE low-level-api/)
target_include_directories(parquet-encryption-legacy-reader PRIVATE low-level-api/)
target_link_libraries(parquet-low-level-example parquet_static)
target_link_libraries(parquet-low-level-example ssl)
target_link_libraries(parquet-low-level-example crypto)
target_link_libraries(parquet-low-level-example2 parquet_static)
target_link_libraries(parquet-low-level-example2 ssl)
target_link_libraries(parquet-low-level-example2 crypto)
target_link_libraries(parquet-encryption-example parquet_static)
target_link_libraries(parquet-encryption-example ssl)
target_link_libraries(parquet-encryption-example crypto)
target_link_libraries(parquet-encryption-interop-writer parquet_static)
target_link_libraries(parquet-encryption-interop-writer ssl)
target_link_libraries(parquet-encryption-interop-writer crypto)
target_link_libraries(parquet-encryption-interop-reader parquet_static)
target_link_libraries(parquet-encryption-interop-reader ssl)
target_link_libraries(parquet-encryption-interop-reader crypto)
target_link_libraries(parquet-encryption-legacy-reader parquet_static)
target_link_libraries(parquet-encryption-legacy-reader ssl)
target_link_libraries(parquet-encryption-legacy-reader crypto)


add_executable(parquet-arrow-example parquet-arrow/reader-writer.cc)
# Prefer shared linkage but use static if shared build is deactivated
if (ARROW_BUILD_SHARED)
  target_link_libraries(parquet-arrow-example parquet_shared)
  target_link_libraries(parquet-arrow-example ssl)
  target_link_libraries(parquet-arrow-example crypto)
else()
  target_link_libraries(parquet-arrow-example parquet_static)
  target_link_libraries(parquet-arrow-example ssl)
  target_link_libraries(parquet-arrow-example crypto)

endif()

add_dependencies(parquet
  parquet-low-level-example
  parquet-low-level-example2
  parquet-encryption-example
  parquet-arrow-example
  parquet-encryption-interop-reader
  parquet-encryption-interop-writer
  parquet-encryption-legacy-reader)
