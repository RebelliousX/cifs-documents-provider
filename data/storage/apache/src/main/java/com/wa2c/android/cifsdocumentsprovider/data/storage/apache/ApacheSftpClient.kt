package com.wa2c.android.cifsdocumentsprovider.data.storage.apache

import com.wa2c.android.cifsdocumentsprovider.common.values.CONNECTION_TIMEOUT
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.StorageConnection
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import org.apache.commons.vfs2.FileSystemOptions
import org.apache.commons.vfs2.provider.sftp.BytesIdentityInfo
import org.apache.commons.vfs2.provider.sftp.SftpFileSystemConfigBuilder
import java.time.Duration

class ApacheSftpClient(
    private val onKeyRead: (String) -> ByteArray,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): ApacheVfsClient(dispatcher) {

    override fun applyOptions(options: FileSystemOptions, storageConnection: StorageConnection) {
        val sftpConnection = storageConnection as StorageConnection.Sftp

        SftpFileSystemConfigBuilder.getInstance().also { builder ->
            builder.setConnectTimeout(options, Duration.ofMillis(CONNECTION_TIMEOUT.toLong()))
            builder.setSessionTimeout(options, Duration.ofMillis(CONNECTION_TIMEOUT.toLong()))
            builder.setPreferredAuthentications(options, "publickey,password")
            builder.setStrictHostKeyChecking(options, "no")
            builder.setFileNameEncoding(options, sftpConnection.encoding)
            // Key
            (sftpConnection.keyData?.encodeToByteArray() ?: sftpConnection.keyFileUri?.let { uri ->
                try { onKeyRead(uri) } catch (e: Exception) { null }
            })?.let { keyBinary ->
                val identity = BytesIdentityInfo(keyBinary, sftpConnection.keyPassphrase?.encodeToByteArray())
                builder.setIdentityProvider(options, identity)
            }
        }
    }

}
