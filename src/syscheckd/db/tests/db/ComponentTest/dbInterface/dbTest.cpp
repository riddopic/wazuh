/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2022, Wazuh Inc.
 * January 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbTest.h"
#include "fimDBHelper.hpp"
#include "dbFileItem.hpp"
#include "db.h"


constexpr auto FIM_DB_TEST {"test.db"};
const auto insertFile = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2456, "gid":0, "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/etc/wgetrc", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":0, "user_name":"fakeUser"}]
    }
)"_json;
const auto insertStatement2 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2221, "gid":0, "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/tmp/test.txt", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":0, "user_name":"fakeUser"}]
    }
)"_json;
const auto insertStatement3 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":8432, "gid":0, "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":99997083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/tmp/test2.txt", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":0, "user_name":"fakeUser"}]
    }
)"_json;
const auto updateStatement1 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"e89f3b4c21c2005896c964462da4766057dd94e9", "dev":2151, "gid":0, "group_name":"root",
        "hash_md5":"d6719d8eaa46012a9de38103d5f284e4", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"0211f049f5b1121fbd034adf7b81ea521d615b5bd8df0e77c8ec8a363459ead1", "inode":18457083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/etc/wgetrc", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":0, "user_name":"fakeUser"}]
    }
)"_json;
const auto updateStatement2 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2151, "gid":0, "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18457083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/tmp/test.txt", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":0, "user_name":"fakeUser"}]
    }
)"_json;

void DBTest::SetUp() {}

void DBTest::TearDown()
{
    std::remove(FIM_DB_TEST);
}

TEST_F(DBTest, TestFimDBInit)
{
    EXPECT_NO_THROW(
    {
        #ifndef WIN32
            fim_db_init(FIM_DB_MEMORY,
                        300,
                        NULL,
                        NULL,
                        MAX_FILE_LIMIT,
                        0,
                        false);
        #else
            fim_db_init(FIM_DB_MEMORY,
                        300,
                        NULL,
                        NULL,
                        MAX_FILE_LIMIT,
                        100000,
                        true);
        #endif
    });
    const auto fileFIMTest { std::make_unique<FileItem>(insertFile["data"][0]) };
    bool updated;
    auto result = fim_db_file_update(fileFIMTest->toFimEntry(), &updated);
    ASSERT_EQ(result, FIMDB_OK);

}

// TEST_F(DBTest, TestFimRunIntegrity)
// {
//     EXPECT_NO_THROW(
//     {
//         fim_run_integrity();
//     });
// }
