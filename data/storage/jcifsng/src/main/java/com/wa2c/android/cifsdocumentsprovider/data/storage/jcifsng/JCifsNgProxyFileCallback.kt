/*
 * Copyright 2017 Google Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wa2c.android.cifsdocumentsprovider.data.storage.jcifsng

import android.os.ProxyFileDescriptorCallback
import android.system.ErrnoException
import android.system.OsConstants
import com.wa2c.android.cifsdocumentsprovider.common.utils.logD
import com.wa2c.android.cifsdocumentsprovider.common.utils.logE
import com.wa2c.android.cifsdocumentsprovider.common.values.AccessMode
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.BackgroundBufferReader
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.BackgroundBufferWriter
import jcifs.smb.SmbFile
import jcifs.smb.SmbRandomAccessFile
import kotlinx.coroutines.*
import kotlin.coroutines.CoroutineContext

/**
 * Optimized Proxy File Callback for jCIFS-ng.
 * - Buffered reader for smooth random access
 * - Async writer for better throughput
 * - Avoids frequent handle switching
 */
internal class JCifsNgProxyFileCallback(
    private val smbFile: SmbFile,
    private val accessMode: AccessMode,
    private val onFileRelease: suspend () -> Unit,
) : ProxyFileDescriptorCallback(), CoroutineScope {

    override val coroutineContext: CoroutineContext = Dispatchers.IO + Job()

    /** File size (lazy to avoid extra network call until needed) */
    private val fileSize: Long by lazy {
        runBlocking(coroutineContext) { smbFile.length() }
    }

    /** Random access handle reused for writing (optional) */
    private var outputAccess: SmbRandomAccessFile? = null

    /** Buffered reader */
    private val readerLazy = lazy {
        BackgroundBufferReader(fileSize) { start, array, off, len ->
            smbFile.openRandomAccess(accessMode.smbMode, SmbFile.FILE_SHARE_READ).use { access ->
                access.seek(start)
                access.read(array, off, len)
            }
        }
    }
    private val reader: BackgroundBufferReader get() = readerLazy.value

    /** Buffered writer */
    private val writerLazy = lazy {
        BackgroundBufferWriter { start, array, off, len ->
            val access = outputAccess ?: smbFile.openRandomAccess(accessMode.smbMode, SmbFile.FILE_SHARE_WRITE)
                .also { outputAccess = it }
            access.seek(start)
            access.write(array, off, len)
        }
    }
    private val writer: BackgroundBufferWriter? get() = if (accessMode == AccessMode.W) writerLazy.value else null

    /** ==================== ProxyFileDescriptorCallback ==================== */

    @Throws(ErrnoException::class)
    override fun onGetSize(): Long = fileSize

    @Throws(ErrnoException::class)
    override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
        if (accessMode != AccessMode.R && accessMode != AccessMode.W) {
            throw ErrnoException("EBADF", OsConstants.EBADF)
        }
        return try {
            runBlocking { reader.readBuffer(offset, size, data) }
        } catch (e: Exception) {
            logE(e)
            throw ErrnoException("EIO", OsConstants.EIO)
        }
    }

    @Throws(ErrnoException::class)
    override fun onWrite(offset: Long, size: Int, data: ByteArray): Int {
        if (accessMode != AccessMode.W) throw ErrnoException("EBADF", OsConstants.EBADF)
        return try {
            writer?.writeBuffer(offset, size, data) ?: 0
        } catch (e: Exception) {
            logE(e)
            throw ErrnoException("EIO", OsConstants.EIO)
        }
    }

    @Throws(ErrnoException::class)
    override fun onFsync() {
        try {
            writer?.close() // flush all buffered writes
        } catch (e: Exception) {
            logE(e)
        }
    }

    @Throws(ErrnoException::class)
    override fun onRelease() {
        logD("onRelease: ${smbFile.uncPath}")
        runBlocking(coroutineContext) {
            try {
                if (readerLazy.isInitialized()) reader.close()
                if (writerLazy.isInitialized()) writer?.close()
                outputAccess?.close()
                onFileRelease()
            } catch (e: Exception) {
                logE(e)
            }
        }
        logD("Release complete: ${smbFile.uncPath}")
    }
}
