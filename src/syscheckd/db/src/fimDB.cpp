/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 27, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimDB.hpp"

void FIMDB::setFileLimit()
{
    m_dbsyncHandler->setTableMaxRow("file_entry", m_fileLimit);
}

void FIMDB::setRegistryLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_key", m_registryLimit);

}

void FIMDB::setValueLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_data", m_registryLimit);

}

void FIMDB::registerRSync()
{
    m_rsyncHandler->registerSyncID(FIM_COMPONENT_FILE,
                                   m_dbsyncHandler->handle(),
                                   nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT),
                                   m_syncFileMessageFunction);

    if (m_isWindows)
    {
        m_rsyncHandler->registerSyncID(FIM_COMPONENT_REGISTRY,
                                       m_dbsyncHandler->handle(),
                                       nlohmann::json::parse(FIM_REGISTRY_SYNC_CONFIG_STATEMENT),
                                       m_syncRegistryMessageFunction);
    }
}

void FIMDB::sync()
{
    m_loggingFunction(LOG_INFO, "Executing FIM sync.");
    m_rsyncHandler->startSync(m_dbsyncHandler->handle(),
                              nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT),
                              m_syncFileMessageFunction);

    if (m_isWindows)
    {
        m_rsyncHandler->startSync(m_dbsyncHandler->handle(),
                                  nlohmann::json::parse(FIM_REGISTRY_START_CONFIG_STATEMENT),
                                  m_syncRegistryMessageFunction);
    }

    m_loggingFunction(LOG_INFO, "Finished FIM sync.");
}

void FIMDB::loopRSync(std::unique_lock<std::mutex>& lock)
{
    m_loggingFunction(LOG_INFO, "FIM sync module started.");
    sync();

    while (!m_cv.wait_for(lock, std::chrono::seconds{m_syncInterval}, [&]()
{
    return m_stopping;
}))
    {
        sync();
    }
    m_rsyncHandler = nullptr;
}

void FIMDB::init(unsigned int syncInterval,
                 fim_sync_callback_t callbackSync,
                 logging_callback_t callbackLog,
                 std::shared_ptr<DBSync> dbsyncHandler,
                 std::shared_ptr<RemoteSync> rsyncHandler,
                 unsigned int fileLimit,
                 unsigned int registryLimit,
                 bool isWindows)
{
    // LCOV_EXCL_START
    std::function<void(const std::string&)> callbackSyncFileWrapper
    {
        [callbackSync](const std::string & msg)
        {
            callbackSync(FIM_COMPONENT_FILE, msg.c_str());
        }
    };

    std::function<void(const std::string&)> callbackSyncRegistryWrapper
    {
        [callbackSync](const std::string & msg)
        {
            callbackSync(FIM_COMPONENT_REGISTRY, msg.c_str());
        }
    };
    // LCOV_EXCL_STOP

    std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
    {
        [callbackLog](modules_log_level_t level, const std::string & log)
        {
            callbackLog(level, log.c_str());
        }
    };

    m_syncInterval = syncInterval;
    m_fileLimit = fileLimit;
    m_registryLimit = registryLimit;

    m_isWindows = isWindows;
    m_dbsyncHandler = dbsyncHandler;
    m_rsyncHandler = rsyncHandler;
    m_syncFileMessageFunction = callbackSyncFileWrapper;
    m_syncRegistryMessageFunction = callbackSyncRegistryWrapper;
    m_loggingFunction = callbackLogWrapper;
    m_stopping = false;

    setFileLimit();

    if (m_isWindows)
    {
        setRegistryLimit();
        setValueLimit();
    }
}

void FIMDB::removeItem(const nlohmann::json& item)
{
    m_dbsyncHandler->deleteRows(item);

}

void FIMDB::updateItem(const nlohmann::json& item, ResultCallbackData callbackData)
{
    m_dbsyncHandler->syncRow(item, callbackData);
}

void FIMDB::executeQuery(const nlohmann::json& item, ResultCallbackData callbackData)
{
    m_dbsyncHandler->selectRows(item, callbackData);
}

void FIMDB::fimRunIntegrity()
{
    std::unique_lock<std::mutex> lock{m_fimSyncMutex};

    registerRSync();
    loopRSync(lock);
}

void FIMDB::fimSyncPushMsg(const std::string& data)
{
    std::unique_lock<std::mutex> lock{m_fimSyncMutex};

    if (!m_stopping)
    {
        auto rawData{data};
        const auto buff{reinterpret_cast<const uint8_t*>(rawData.c_str())};

        try
        {
            m_rsyncHandler->pushMessage(std::vector<uint8_t> {buff, buff + rawData.size()});
            m_loggingFunction(LOG_DEBUG_VERBOSE, "Message pushed: " + data);
        }
        // LCOV_EXCL_START
        catch (const std::exception& ex)
        {
            m_loggingFunction(LOG_ERROR, ex.what());
        }

        // LCOV_EXCL_STOP
    }
}
