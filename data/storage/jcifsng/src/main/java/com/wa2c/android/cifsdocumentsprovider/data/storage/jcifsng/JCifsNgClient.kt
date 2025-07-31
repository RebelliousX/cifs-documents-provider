package com.wa2c.android.cifsdocumentsprovider.data.storage.jcifsng

import android.os.Handler
import android.os.Looper
import android.os.ProxyFileDescriptorCallback
import android.util.LruCache
import com.wa2c.android.cifsdocumentsprovider.common.exception.StorageException
import com.wa2c.android.cifsdocumentsprovider.common.utils.isDirectoryUri
import com.wa2c.android.cifsdocumentsprovider.common.utils.logD
import com.wa2c.android.cifsdocumentsprovider.common.utils.logE
import com.wa2c.android.cifsdocumentsprovider.common.utils.logW
import com.wa2c.android.cifsdocumentsprovider.common.utils.throwStorageCommonException
import com.wa2c.android.cifsdocumentsprovider.common.values.AccessMode
import com.wa2c.android.cifsdocumentsprovider.common.values.CACHE_TIMEOUT
import com.wa2c.android.cifsdocumentsprovider.common.values.CONNECTION_TIMEOUT
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
import jcifs.internal.SMBSigningDigest
import jcifs.smb.NtStatus
import jcifs.smb.NtlmPasswordAuthenticator
import jcifs.smb.SmbAuthException
import jcifs.smb.SmbException
import jcifs.smb.SmbFile
import jcifs.smb.SmbUnsupportedOperationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Properties
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * JCIFS-ng Client
 */
class JCifsNgClient(
    private val isSmb1: Boolean,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
): StorageClient {

    /** Active file count */
    private val activeFileCount = AtomicInteger(0)

    /** Active files by URI */
    private val activeFiles = ConcurrentHashMap<String, Int>()

    /** Handler for delayed operations */
    private val handler = Handler(Looper.getMainLooper())

    /** post delay in milliseconds to decrement active file count after a file is released */
    private val delayDecrement = 250

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
            setProperty("jcifs.smb.client.signingPreferred", connection.enableJcifsSecuritySignature.toString())
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
    private fun getSmbFile(request: StorageRequest, ignoreCache: Boolean = false, existsRequired: Boolean = false): SmbFile {
        val connection = request.connection as StorageConnection.Cifs
        val context = getCifsContext(connection, ignoreCache)
        return SmbFile(request.uri, context).apply {
            connectTimeout = CONNECTION_TIMEOUT
            readTimeout = READ_TIMEOUT
        }.also {
            if (existsRequired && !it.exists()) throw StorageException.File.NotFound()
        }
    }

    /**
     * Convert SmbFile to StorageFile
     */
    private fun SmbFile.toStorageFile(): StorageFile {
        val urlText = url.toString()
        val isDir = urlText.isDirectoryUri || isDirectory
        return StorageFile(
            name = name.trim('/'),
            uri = urlText,
            size = if (isDir || !isFile) 0 else length(),
            lastModified = lastModified,
            isDirectory = isDir,
        )
    }

    private suspend fun <T> runHandling(
        request: StorageRequest,
        block: suspend CoroutineScope.() -> T
    ): T {
        return withContext(dispatcher) {
            try {
                return@withContext block()
            } catch (e: Exception) {
                logE(e)
                val c = e.getCause()
                c.throwStorageCommonException()
                when (c) {
                    is SmbUnsupportedOperationException -> {
                        throw StorageException.Operation.Unsupported(e)
                    }
                    is SmbAuthException -> {
                        throw StorageException.Security.Auth(e, request.connection.id)
                    }
                    is SmbException -> {
                        if (c.ntStatus in warningStatus) throw StorageException.File.NotFound(e)
                        else throw StorageException.Error(e)
                    }
                }
                throw StorageException.Error(e)
            }
        }
    }

    /**
     * Get file
     */
    override suspend fun getFile(request: StorageRequest, ignoreCache: Boolean): StorageFile {
        return  runHandling(request) {
            getSmbFile(request, ignoreCache = ignoreCache, existsRequired = true).use { it.toStorageFile() }
        }
    }

    /**
     * Get children StorageFile list
     */
    override suspend fun getChildren(request: StorageRequest, ignoreCache: Boolean): List<StorageFile> {
        return  runHandling(request) {
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
        return runHandling(request) {
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
        return runHandling(request) {
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
        return runHandling(sourceRequest) {
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
        return runHandling(request) {
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
        return runHandling(sourceRequest) {
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
        return runHandling(request) {
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
        return runHandling(request) {
            val file = getSmbFile(request, existsRequired = true).takeIf { it.isFile } ?: throw StorageException.File.NotFound()

            val fileUri = request.uri

            // Get current connection counts
            val currentFileCount = activeFiles.getOrDefault(fileUri, 0) + 1
            val currentGlobalCount = activeFileCount.incrementAndGet()

            // Update file-specific count
            activeFiles[fileUri] = currentFileCount

            // Determine callback type:
            // Use safe callback if:
            // 1. Explicitly enabled in connection settings
            // 2. Multiple files open globally
            // Use Native I/O (non-safe proxy callback) only if there is one file opened globally
            // but if the same file is opened more than once within delay period, then do not use
            // safe callback
            var useSafe = request.connection.safeTransfer || currentGlobalCount > 1
            // some apps have bizarre file operation. They open a file, read some data, close it
            // then open it again within milliseconds. We want to use buffered mode in case file
            // is big and using safe callbacks then will be extremely slow (about 6 times slower).
            if (currentFileCount > 1) useSafe = false

            val release: suspend () -> Unit = {
                try {
                    file.close()
                } catch (e: Exception) {
                    logE(e)
                } finally {
                    // Schedule cleanup after sequential window
                    handler.postDelayed({
                        // Decrement global count
                        activeFileCount.decrementAndGet()

                        // Decrement file-specific count
                        activeFiles.computeIfPresent(fileUri) { _, count ->
                            if (count > 1) count - 1 else null
                        }
                    }, delayDecrement.toLong())

                    onFileRelease()
                }
            }

            if (useSafe) {
                JCifsNgProxyFileCallbackSafe(file, mode, release)
            } else {
                JCifsNgProxyFileCallback(file, mode, release)
            }
        }
    }

    override suspend fun removeCache(request: StorageRequest?): Boolean {
        return if (request == null) {
            contextCache.evictAll()
            true
        } else {
            contextCache.remove(request.connection) != null
        }
    }

    override suspend fun close() {
        removeCache()
    }

    companion object {
        /** Warning status */
        private val warningStatus = arrayOf(
            NtStatus.NT_STATUS_BAD_NETWORK_NAME, // No root folder
            NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, // No sub folder
        )
    }

}
