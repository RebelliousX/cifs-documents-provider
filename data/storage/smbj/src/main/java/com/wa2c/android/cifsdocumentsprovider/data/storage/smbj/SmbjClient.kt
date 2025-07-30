package com.wa2c.android.cifsdocumentsprovider.data.storage.smbj

import android.os.Handler
import android.os.Looper
import android.os.ProxyFileDescriptorCallback
import android.util.LruCache
import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.mserref.NtStatus
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.msfscc.fileinformation.FileAllInformation
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.protocol.commons.EnumWithValue
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskEntry
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.share.File
import com.rapid7.client.dcerpc.mssrvs.ServerService
import com.rapid7.client.dcerpc.transport.SMBTransportFactories
import com.wa2c.android.cifsdocumentsprovider.common.exception.StorageException
import com.wa2c.android.cifsdocumentsprovider.common.utils.appendChild
import com.wa2c.android.cifsdocumentsprovider.common.utils.fileName
import com.wa2c.android.cifsdocumentsprovider.common.utils.isDirectoryUri
import com.wa2c.android.cifsdocumentsprovider.common.utils.logD
import com.wa2c.android.cifsdocumentsprovider.common.utils.logE
import com.wa2c.android.cifsdocumentsprovider.common.utils.logW
import com.wa2c.android.cifsdocumentsprovider.common.utils.throwStorageCommonException
import com.wa2c.android.cifsdocumentsprovider.common.values.AccessMode
import com.wa2c.android.cifsdocumentsprovider.common.values.BUFFER_SIZE
import com.wa2c.android.cifsdocumentsprovider.common.values.OPEN_FILE_LIMIT_DEFAULT
import com.wa2c.android.cifsdocumentsprovider.common.values.OPEN_FILE_LIMIT_MAX
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageClient
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageConnection
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageFile
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageRequest
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.getCause
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.isInvalidFileName
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.rename
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.toUncSeparator
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.uncPathToUri
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * SMBJ Client
 */
class SmbjClient(
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
): StorageClient {
    
    /** Active file count */
    private val activeFileCount = AtomicInteger(0)

    /** Active files by URI */
    private val activeFiles = ConcurrentHashMap<String, Int>()

    /** Handler for delayed operations */
    private val handler = Handler(Looper.getMainLooper())

    /** Sequential operation window */
    private val sequentialWindowMs = 250

    /** Session cache */
    private val sessionCache = object : LruCache<StorageConnection, Session>(OPEN_FILE_LIMIT_MAX) {
        override fun entryRemoved(evicted: Boolean, key: StorageConnection?, oldValue: Session?, newValue: Session?) {
            try {
                if (oldValue?.connection?.isConnected == true) {
                    oldValue.close()
                    logD("Session Disconnected: ${key?.name}")
                }
            } catch (e: Exception) {
                logE(e)
            }
            super.entryRemoved(evicted, key, oldValue, newValue)
            logD("Session Removed: ${key?.name}")
        }
    }

    /** DiskShare cache */
    private val diskShareCache = object : LruCache<StorageConnection, DiskShare>(OPEN_FILE_LIMIT_DEFAULT) {
        override fun entryRemoved(evicted: Boolean, key: StorageConnection?, oldValue: DiskShare?, newValue: DiskShare?) {
            try {
                if (oldValue?.isConnected == true) {
                    oldValue.close()
                    logD("DiskShare Disconnected: ${key?.name}")
                }
            } catch (e: Exception) {
                logE(e)
            }
            super.entryRemoved(evicted, key, oldValue, newValue)
            logD("DiskShare Removed: ${key?.name}")
        }
    }

    /**
     * Get session
     */
    private fun getSession(connection: StorageConnection.Cifs, forced: Boolean = false): Session {
        return if (!forced) { sessionCache[connection]?.takeIf { it.connection.isConnected } } else { null } ?: let {
            val configBuilder = SmbConfig.builder()
                .withDfsEnabled(connection.enableDfs)
                .withEncryptData(connection.enableEncryption)

            if (connection.enableEncryption) {
                // encryption is a must with smb 3.x dialects
                configBuilder.withDialects(
                    SMB2Dialect.SMB_3_1_1,
                    SMB2Dialect.SMB_3_0_2,
                    SMB2Dialect.SMB_3_0
                )
            } else {
                // Signing is required for SMB dialects 3.x. Connection testing
                // will throw an error that signing can not be disabled for 3.x.
                // So, we opt for SMB dialect 2.x *ONLY* if both encryption and signing
                // are both disabled. This resulting in a big speed boost ranging from 25%
                // to 50% or higher. Even 300%+ is possible if accompanied with Safe Data Transfer.
                if (!connection.enableSmbjSecuritySignature) {
                    configBuilder.withDialects(
                        SMB2Dialect.SMB_2_1,
                        SMB2Dialect.SMB_2_0_2
                    )
                }
            }
            configBuilder.withSigningEnabled(connection.enableSmbjSecuritySignature)

            val config = configBuilder.build()
            val client = SMBClient(config)
            val port = connection.port?.toIntOrNull()

            val context = when {
                connection.isAnonymous -> AuthenticationContext.anonymous() // Anonymous
                connection.isGuest -> AuthenticationContext.guest() // Guest if empty username
                else -> AuthenticationContext(
                    connection.user,
                    (connection.password ?: "").toCharArray(),
                    connection.domain
                )
            }

            (port?.let { client.connect(connection.host, it) } ?: client.connect(connection.host))
                .authenticate(context).also { sessionCache.put(connection, it) }
        }
    }

    /**
     * Check file exists
     */
    private fun DiskShare.exists(path: String): Boolean {
        return try {
            if (path.isEmpty()) true
            else if (path.isDirectoryUri) folderExists(path)
            else fileExists(path)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get DiskShare
     */
    private fun <T> useDiskShare(request: StorageRequest, ignoreCache: Boolean = false, process: (DiskShare) -> T): T {
        val connection = request.connection as StorageConnection.Cifs
        val key = connection.copy(folder = request.shareName)
        val diskShare = if (!ignoreCache) { diskShareCache[key]?.takeIf { it.isConnected } } else { null } ?: let {
            (getSession(connection, ignoreCache).connectShare(request.shareName) as DiskShare).also {
                diskShareCache.put(key, it)
            }
        }
        return process(diskShare)
    }


    /**
     * Open File
     */
    private fun openDiskFile(diskShare: DiskShare, sharePath: String, isRead: Boolean, existsRequired: Boolean = false): File {
        if (existsRequired && !diskShare.exists(sharePath)) throw StorageException.File.NotFound()
        return if (isRead) {
            diskShare.openFile(
                sharePath.ifEmpty { "/" },
                setOf(AccessMask.GENERIC_READ),
                setOf(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                setOf(SMB2ShareAccess.FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_OPEN,
                null,
            )
        } else {
            diskShare.openFile(
                sharePath,
                setOf(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE, AccessMask.DELETE),
                setOf(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OPEN_IF,
                null,
            )
        }
    }

    private fun FileAllInformation.toStorageFile(uriText: String): StorageFile {
        return StorageFile(
            name = uriText.fileName,
            uri = uriText,
            size = standardInformation.endOfFile,
            lastModified = basicInformation.changeTime.toEpochMillis(),
            isDirectory = standardInformation.isDirectory
        )
    }

    private fun DiskEntry.toStorageFile(): StorageFile {
        val isDirectory = this.fileInformation.standardInformation.isDirectory
        val uri = this.uncPath.uncPathToUri(isDirectory) ?: throw StorageException.File.NotFound()
        return StorageFile(
            name = uri.fileName,
            uri = uri,
            size = this.fileInformation.standardInformation.endOfFile,
            lastModified = this.fileInformation.basicInformation.changeTime.toEpochMillis(),
            isDirectory = isDirectory
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
                    is SMBApiException -> {
                        if (c.status == NtStatus.STATUS_ACCESS_DENIED || c.status == NtStatus.STATUS_LOGON_FAILURE) {
                            throw StorageException.Security.Auth(e, request.connection.id)
                        } else if (c.status == NtStatus.STATUS_BAD_NETWORK_NAME || c.status == NtStatus.STATUS_BAD_NETWORK_PATH) {
                            throw StorageException.File.NotFound(e)
                        }
                    }
                }
                throw StorageException.Error(e)
            }
        }
    }

    override suspend fun getFile(request: StorageRequest, ignoreCache: Boolean): StorageFile {
        return runHandling(request) {
            if (request.isRoot || request.isShareRoot) {
                StorageFile(
                    request.connection.name,
                    request.connection.uri,
                    0,
                    0,
                    true,
                )
            } else {
                useDiskShare(request, ignoreCache) { diskShare ->
                    if (!diskShare.exists(request.sharePath)) throw StorageException.File.NotFound()
                    val info = diskShare.getFileInformation(request.sharePath)
                    info.toStorageFile(request.uri)
                }
            }
        }
    }

    override suspend fun getChildren(request: StorageRequest, ignoreCache: Boolean): List<StorageFile> {
        return runHandling(request) {
            if (request.isRoot) {
                // Root
                val connection = request.connection as StorageConnection.Cifs
                val session = getSession(connection, ignoreCache)
                val transport = SMBTransportFactories.SRVSVC.getTransport(session)
                val serverService = ServerService(transport)
                serverService.shares0
                    .filter { !it.netName.isInvalidFileName }
                    .map { info ->
                        StorageFile(
                            name = info.netName,
                            uri = request.uri.appendChild(info.netName, true),
                            size = 0,
                            lastModified = 0,
                            isDirectory = true,
                        )
                    }
            } else {
                // Shared folder
                useDiskShare(request, ignoreCache) { diskShare ->
                    if (!diskShare.exists(request.sharePath)) throw StorageException.File.NotFound()
                    diskShare.list(request.sharePath)
                        .filter { !it.fileName.isInvalidFileName }
                        .map { info ->
                            val isDirectory = EnumWithValue.EnumUtils.isSet(
                                info.fileAttributes,
                                FileAttributes.FILE_ATTRIBUTE_DIRECTORY
                            )
                            StorageFile(
                                name = info.fileName,
                                uri = request.uri.appendChild(info.fileName, isDirectory),
                                size = info.endOfFile,
                                lastModified = info.changeTime.toEpochMillis(),
                                isDirectory = isDirectory,
                            )
                        }
                }
            }
        }
    }


    override suspend fun createDirectory(
        request: StorageRequest,
    ): StorageFile {
        return runHandling(request) {
            useDiskShare(request) { diskShare ->
                diskShare.mkdir(request.sharePath)
                diskShare.getFileInformation(request.sharePath)
            }.toStorageFile(request.uri)
        }
    }

    override suspend fun createFile(request: StorageRequest): StorageFile {
        return runHandling(request) {
            useDiskShare(request) { diskShare ->
                openDiskFile(diskShare, request.sharePath, isRead = false).use { f ->
                    f.fileInformation
                }
            }.toStorageFile(request.uri)
        }
    }

    override suspend fun copyFile(
        sourceRequest: StorageRequest,
        targetRequest: StorageRequest,
    ): StorageFile {
        return runHandling(sourceRequest) {
            useDiskShare(sourceRequest) { diskShare ->
                useDiskShare(targetRequest) { targetDiskShare ->
                    openDiskFile(diskShare, sourceRequest.sharePath, isRead = true, existsRequired = true).use { sourceEntry ->
                        openDiskFile(targetDiskShare, targetRequest.sharePath, isRead = false).use { targetEntry ->
                            // Copy
                            sourceEntry.remoteCopyTo(targetEntry)
                            targetEntry.toStorageFile()
                        }
                    }
                }
            }
        }
    }

    override suspend fun renameFile(
        request: StorageRequest,
        newName: String,
    ): StorageFile {
        return runHandling(request) {
            useDiskShare(request) { diskShare ->
                openDiskFile(diskShare, request.sharePath, isRead = false, existsRequired = true).use { diskEntry ->
                    val newPath = request.sharePath.rename(newName)
                    diskEntry.rename(newPath.toUncSeparator())
                    diskEntry.toStorageFile()
                }
            }
        }
    }

    override suspend fun moveFile(
        sourceRequest: StorageRequest,
        targetRequest: StorageRequest,
    ): StorageFile {
        return runHandling(sourceRequest) {
            useDiskShare(sourceRequest) { diskShare ->
                openDiskFile(diskShare, sourceRequest.sharePath, isRead = false, existsRequired = true).use { diskEntry ->
                    diskEntry.rename(targetRequest.sharePath.toUncSeparator())
                    diskEntry.toStorageFile()
                }
            }
        }
    }

    override suspend fun deleteFile(request: StorageRequest): Boolean {
        return runHandling(request) {
            try {
                useDiskShare(request) { diskShare ->
                    diskShare.rm(request.sharePath)
                }
                true
            } catch (e: Exception) {
                logW(e)
                false
            }
        }
    }

    override suspend fun getProxyFileDescriptorCallback(
        request: StorageRequest,
        mode: AccessMode,
        onFileRelease: suspend () -> Unit
    ): ProxyFileDescriptorCallback {
        return runHandling(request) {
            val diskFile = useDiskShare(request) {
                openDiskFile(it, request.sharePath, isRead = mode == AccessMode.R, existsRequired = true)
            }.takeIf { !it.fileInformation.standardInformation.isDirectory }
                ?: throw StorageException.File.NotFound()

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
            val useSafe = request.connection.safeTransfer || currentGlobalCount > 1

            val release: suspend () -> Unit = {
                try {
                    diskFile.closeSilently()
                } finally {
                    // Schedule cleanup after sequential window
                    handler.postDelayed({
                        // Decrement global count
                        activeFileCount.decrementAndGet()

                        // Decrement file-specific count
                        activeFiles.computeIfPresent(fileUri) { _, count ->
                            if (count > 1) count - 1 else null
                        }
                    }, sequentialWindowMs.toLong())

                    onFileRelease()
                }
            }

            if (useSafe) {
                SmbjProxyFileCallbackSafe(diskFile, mode, release)
            } else {
                // Use buffered for single file, even with multiple connections
                SmbjProxyFileCallback(diskFile, mode, release)
            }
        }
    }

    override suspend fun removeCache(request: StorageRequest?): Boolean {
        return if (request == null) {
            diskShareCache.evictAll()
            sessionCache.evictAll()
            true
        } else {
            diskShareCache.remove(request.connection)
            sessionCache.remove(request.connection) != null
        }
    }

    override suspend fun close() {
        removeCache()
    }

}
