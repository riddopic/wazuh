/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef FIM_DB_WRAPPERS_H
#define FIM_DB_WRAPPERS_H

#include "syscheckd/syscheck.h"

int __wrap_fim_db_get_checksum_range(fdb_t *fim_sql,
                                     fim_type type,
                                     const char *start,
                                     const char *top,
                                     int n,
                                     EVP_MD_CTX *ctx_left,
                                     EVP_MD_CTX *ctx_right,
                                     char **str_pathlh,
                                     char **str_pathuh);

int __wrap_fim_db_delete_not_scanned(fdb_t * fim_sql,
                                     fim_tmp_file *file,
                                     pthread_mutex_t *mutex,
                                     int storage);

int __wrap_fim_db_get_count_file_entry(fdb_t * fim_sql);

int __wrap_fim_db_get_count_range(fdb_t *fim_sql,
                                  fim_type type,
                                  char *start,
                                  char *top,
                                  int *count);

fim_entry *__wrap_fim_db_get_path(fdb_t *fim_sql,
                                  const char *file_path);

fdb_t *__wrap_fim_db_init(int memory);

int __wrap_fim_db_process_missing_entry(fdb_t *fim_sql,
                                        fim_tmp_file *file,
                                        pthread_mutex_t *mutex,
                                        int storage,
                                        event_data_t *evt_data);

int __wrap_fim_db_remove_path(fdb_t *fim_sql, char *path);

int __wrap_fim_db_sync_path_range(fdb_t *fim_sql,
                                  pthread_mutex_t *mutex,
                                  fim_tmp_file *file,
                                  int storage);

int __wrap_fim_db_get_count_entries(fdb_t *fim_sql);


#ifndef WIN32
fim_entry *__wrap_fim_db_get_entry_from_sync_msg(fdb_t *fim_sql,
                                                 __attribute__((unused)) fim_type type,
                                                 const char *path);

#else
fim_entry *__wrap_fim_db_get_entry_from_sync_msg(fdb_t *fim_sql, fim_type type, const char *path);
#endif

int __wrap_fim_db_read_line_from_file(fim_tmp_file *file, int storage, int it, char **buffer);

void __wrap_fim_db_clean_file(fim_tmp_file **file, int storage);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_db_get_count_entries
 */
void expect_wrapper_fim_db_get_count_entries(const fdb_t *fim_sql, int ret);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_db_remove_path
 */
void expect_fim_db_remove_path(fdb_t *fim_sql, char *path, int ret_val);

int __wrap_fim_db_file_is_scanned(__attribute__((unused)) fdb_t *fim_sql, const char *path);

int __wrap_fim_db_data_exists(__attribute__((unused)) fdb_t *fim_sql, unsigned long int inode, unsigned long int dev);

int __wrap_fim_db_append_paths_from_inode(fdb_t *fim_sql,
                                          unsigned long int inode,
                                          unsigned long int dev,
                                          OSList *list,
                                          rb_tree *tree);

int __wrap_fim_db_file_update(fdb_t *fim_sql,
                              const char *path,
                              const __attribute__((unused)) fim_file_data *data,
                              fim_entry **saved);

#endif
