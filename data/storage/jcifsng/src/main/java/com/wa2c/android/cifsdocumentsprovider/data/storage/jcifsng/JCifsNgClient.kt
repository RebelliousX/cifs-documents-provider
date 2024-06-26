package com.wa2c.android.cifsdocumentsprovider.data.storage.jcifsng

import android.os.ProxyFileDescriptorCallback
import android.util.LruCache
import com.wa2c.android.cifsdocumentsprovider.common.exception.StorageException
import com.wa2c.android.cifsdocumentsprovider.common.utils.isDirectoryUri
import com.wa2c.android.cifsdocumentsprovider.common.utils.logD
import com.wa2c.android.cifsdocumentsprovider.common.utils.logE
import com.wa2c.android.cifsdocumentsprovider.common.utils.logW
import com.wa2c.android.cifsdocumentsprovider.common.values.AccessMode
import com.wa2c.android.cifsdocumentsprovider.common.values.CACHE_TIMEOUT
import com.wa2c.android.cifsdocumentsprovider.common.values.CONNECTION_TIMEOUT
import com.wa2c.android.cifsdocumentsprovider.common.values.ConnectionResult
import com.wa2c.android.cifsdocumentsprovider.common.values.OPEN_FILE_LIMIT_MAX
import com.wa2c.android.cifsdocumentsprovider.common.values.READ_TIMEOUT
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageClient
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageConnection
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageFile
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageRequest
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.getCause
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.rename
import jcifs.CIFSContext
import jcifs.config.PropertyConfiguration
import jcifs.context.BaseContext
import jcifs.context.CIFSContextWrapper
import jcifs.smb.NtStatus
import jcifs.smb.NtlmPasswordAuthenticator
import jcifs.smb.SmbException
import jcifs.smb.SmbFile
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Properties


/**
 * JCIFS-ng Client
 */
class JCifsNgClient(
    private val isSmb1: Boolean,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
): StorageClient {

    /** Session cache */
    private val contextCache = object : LruCache<StorageConnection, CIFSContext>(OPEN_FILE_LIMIT_MAX) {
        override fun entryRemoved(evicted: Boolean, key: StorageConnection?, oldValue: CIFSContext?, newValue: CIFSContext?) {
            try {
                oldValue?.close()
                logD("Session Disconnected: ${key?.name}")
            } catch (e: Exception) {
                logE(e)
            }
            super.entryRemoved(evicted, key, oldValue, newValue)
            logD("Session Removed: $key")
        }
    }

    /**
     * Get auth by user. Anonymous if user and password are empty.
     */
    private fun getCifsContext(
        connection: StorageConnection.Cifs,
        ignoreCache: Boolean,
    ): CIFSContext {
        if (!ignoreCache) { contextCache[connection]?.let { return it } }

        val property = Properties().apply {
            if (isSmb1) {
                setProperty("jcifs.smb.client.minVersion", "SMB1")
                setProperty("jcifs.smb.client.maxVersion", "SMB1")
            } else {
                setProperty("jcifs.smb.client.minVersion", "SMB202")
                setProperty("jcifs.smb.client.maxVersion", "SMB311")
            }
            setProperty("jcifs.smb.client.responseTimeout", READ_TIMEOUT.toString())
            setProperty("jcifs.smb.client.connTimeout", CONNECTION_TIMEOUT.toString())
            setProperty("jcifs.smb.client.attrExpirationPeriod", CACHE_TIMEOUT.toString())
            setProperty("jcifs.smb.client.dfs.disabled", (!connection.enableDfs).toString())
            setProperty("jcifs.smb.client.ipcSigningEnforced", (!connection.user.isNullOrEmpty() && connection.user != "guest").toString())
            setProperty("jcifs.smb.client.guestUsername", "cifs-documents-provider")
        }

        val context = BaseContext(PropertyConfiguration(property)).let {
            when {
                connection.isAnonymous -> it.withAnonymousCredentials() // Anonymous
                connection.isGuest -> it.withGuestCrendentials() // Guest if empty username
                else -> it.withCredentials(NtlmPasswordAuthenticator(connection.domain, connection.user, connection.password, null))
            }
        }
        logD("CIFSContext Created: $context")
        return CIFSContextWrapper(context).also {
            contextCache.put(connection, it)
        }
    }

    /**
     * Get SMB file
     */
    private suspend fun getSmbFile(request: StorageRequest, ignoreCache: Boolean = false, existsRequired: Boolean = false): SmbFile {
        return withContext(dispatcher) {
            val connection = request.connection as StorageConnection.Cifs
            val context = getCifsContext(connection, ignoreCache)
            SmbFile(request.uri, context).apply {
                connectTimeout = CONNECTION_TIMEOUT
                readTimeout = READ_TIMEOUT
            }.also {
                if (existsRequired && !it.exists()) throw StorageException.FileNotFoundException()
            }
        }
    }

    /**
     * Convert SmbFile to StorageFile
     */
    private suspend fun SmbFile.toStorageFile(): StorageFile {
        val urlText = url.toString()
        return withContext(dispatcher) {
            val isDir = urlText.isDirectoryUri || isDirectory
            StorageFile(
                name = name.trim('/'),
                uri = urlText,
                size = if (isDir || !isFile) 0 else length(),
                lastModified = lastModified,
                isDirectory = isDir,
            )
        }
    }

    /**
     * Check setting connectivity.
     */
    override suspend fun checkConnection(request: StorageRequest): ConnectionResult {
        return withContext(dispatcher) {
            try {
                getChildren(request, true).let {
                    ConnectionResult.Success
                }
            } catch (e: Exception) {
                logW(e)
                val c = e.getCause()
                if (c is SmbException && c.ntStatus in warningStatus) {
                    // Warning
                    ConnectionResult.Warning(c)
                } else if (c is StorageException.FileNotFoundException) {
                    ConnectionResult.Warning(c)
                } else {
                    // Failure
                    ConnectionResult.Failure(c)
                }
            } finally {
                contextCache.remove(request.connection)
            }
        }
    }

    /**
     * Get file
     */
    override suspend fun getFile(request: StorageRequest, ignoreCache: Boolean): StorageFile {
        return  withContext(dispatcher) {
            getSmbFile(request, ignoreCache = ignoreCache, existsRequired = true).use { it.toStorageFile() }
        }
    }

    /**
     * Get children StorageFile list
     */
    override suspend fun getChildren(request: StorageRequest, ignoreCache: Boolean): List<StorageFile> {
        return  withContext(dispatcher) {
            getSmbFile(request, ignoreCache = ignoreCache).use { parent ->
                parent.listFiles().map { child ->
                    child.use { it.toStorageFile() }
                }
            }
        }
    }

    /**
     * Create new directory.
     */
    override suspend fun createDirectory(request: StorageRequest): StorageFile {
        return withContext(dispatcher) {
            getSmbFile(request).use {
                it.mkdir()
                it.toStorageFile()
            }
        }
    }

    /**
     * Create new file.
     */
    override suspend fun createFile(request: StorageRequest): StorageFile {
        return withContext(dispatcher) {
            getSmbFile(request).use { file ->
                file.createNewFile()
                file.toStorageFile()
            }
        }
    }

    /**
     * Copy file
     */
    override suspend fun copyFile(
        sourceRequest: StorageRequest,
        targetRequest: StorageRequest,
    ): StorageFile {
        return withContext(dispatcher) {
            getSmbFile(sourceRequest, existsRequired = true).use { source ->
                getSmbFile(targetRequest).use { target ->
                    source.copyTo(target)
                    target.toStorageFile()
                }
            }
        }
    }

    /**
     * Rename file
     */
    override suspend fun renameFile(
        request: StorageRequest,
        newName: String,
    ): StorageFile {
        return withContext(dispatcher) {
            getSmbFile(request, existsRequired = true).use { source ->
                val targetUri = request.uri.rename(newName)
                getSmbFile(request.replacePathByUri(targetUri)).use { target ->
                    source.renameTo(target)
                    target.toStorageFile()
                }
            }
        }
    }

    /**
     * Move file
     */
    override suspend fun moveFile(
        sourceRequest: StorageRequest,
        targetRequest: StorageRequest,
    ): StorageFile {
        return withContext(dispatcher) {
            if (sourceRequest.connection == targetRequest.connection) {
                // Same connection
                getSmbFile(sourceRequest, existsRequired = true).use { source ->
                    getSmbFile(targetRequest).use { target ->
                        source.renameTo(target)
                        target.toStorageFile()
                    }
                }
            } else {
                // Different connection
                copyFile(sourceRequest, targetRequest).also {
                    deleteFile(sourceRequest)
                }
            }
        }
    }

    /**
     * Delete file
     */
    override suspend fun deleteFile(
        request: StorageRequest,
    ): Boolean {
        return withContext(dispatcher) {
            try {
                getSmbFile(request, existsRequired = true).use {
                    it.delete()
                }
                true
            } catch (e: Exception) {
                logW(e)
                false
            }
        }
    }

    /**
     * Get ProxyFileDescriptorCallback
     */
    override suspend fun getProxyFileDescriptorCallback(
        request: StorageRequest,
        mode: AccessMode,
        onFileRelease: suspend () -> Unit
    ): ProxyFileDescriptorCallback {
        return withContext(dispatcher) {
            val file = getSmbFile(request, existsRequired = true).takeIf { it.isFile } ?: throw StorageException.FileNotFoundException()
            val release: suspend () -> Unit = {
                try { file.close() } catch (e: Exception) { logE(e) }
                onFileRelease()
            }

            if (request.connection.safeTransfer) {
                JCifsNgProxyFileCallbackSafe(file, mode, release)
            } else {
                JCifsNgProxyFileCallback(file, mode, release)
            }
        }
    }

    override suspend fun close() {
        contextCache.evictAll()
    }

    companion object {
        /** Warning status */
        private val warningStatus = arrayOf(
            NtStatus.NT_STATUS_BAD_NETWORK_NAME, // No root folder
            NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, // No sub folder
        )
    }

}
