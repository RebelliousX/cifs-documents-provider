package com.wa2c.android.cifsdocumentsprovider.data.storage.smbj

import android.os.ProxyFileDescriptorCallback
import android.system.ErrnoException
import android.system.OsConstants
import com.hierynomus.smbj.share.File
import com.wa2c.android.cifsdocumentsprovider.common.utils.logD
import com.wa2c.android.cifsdocumentsprovider.common.utils.logE
import com.wa2c.android.cifsdocumentsprovider.common.values.AccessMode
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.BackgroundBufferReader
import com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils.BackgroundBufferWriter
import kotlinx.coroutines.*
import kotlin.coroutines.CoroutineContext

/**
 * Optimized Proxy File Callback for SMBJ.
 * - Buffered reads for random access
 * - Async buffered writes
 */
class SmbjProxyFileCallback(
    private val file: File,
    private val accessMode: AccessMode,
    private val onFileRelease: suspend () -> Unit
) : ProxyFileDescriptorCallback(), CoroutineScope {

    override val coroutineContext: CoroutineContext = Dispatchers.IO + Job()

    /** File size (lazy to avoid SMB request until needed) */
    private val fileSize: Long by lazy {
        runBlocking(coroutineContext) { file.fileInformation.standardInformation.endOfFile }
    }

    /** Buffered reader for low-latency random access */
    private val readerLazy = lazy {
        BackgroundBufferReader(fileSize) { start, array, off, len ->
            file.read(array, start, off, len)
        }
    }

    private val reader: BackgroundBufferReader get() = readerLazy.value

    /** Buffered writer for async writes (only created if writable) */
    private val writerLazy = lazy {
        BackgroundBufferWriter() { start, array, off, len ->
            file.write(array, start, off, len)
        }
    }

    private val writer: BackgroundBufferWriter?
        get() = if (accessMode == AccessMode.W) writerLazy.value else null

    /** ==================== ProxyFileDescriptorCallback ==================== */

    @Throws(ErrnoException::class)
    override fun onGetSize(): Long = fileSize

    /**
     * Optimized synchronous read
     */
    @Throws(ErrnoException::class)
    override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
        if (accessMode == AccessMode.W) {
            // W mode can also read because SAF "rw" allows read
        } else if (accessMode != AccessMode.R) {
            throw ErrnoException("EBADF", OsConstants.EBADF)
        }
        return try {
            runBlocking {
                reader.readBuffer(offset, size, data)
            }
        } catch (e: Exception) {
            logE(e)
            throw ErrnoException("EIO", OsConstants.EIO)
        }
    }

    /**
     * Buffered async write (enqueue to writer)
     */
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

    /**
     * Called on fsync, ensure buffers are flushed
     */
    @Throws(ErrnoException::class)
    override fun onFsync() {
        try {
            writer?.close() // flush any remaining buffer
        } catch (e: Exception) {
            logE(e)
        }
    }

    /**
     * Called when FD is released
     */
    @Throws(ErrnoException::class)
    override fun onRelease() {
        logD("onRelease: ${file.uncPath}")
        runBlocking(coroutineContext) {
            try {
                if (readerLazy.isInitialized()) reader.close()
                if (writerLazy.isInitialized()) writer?.close()
                onFileRelease()
            } catch (e: Exception) {
                logE(e)
            }
        }
        logD("Release complete: ${file.uncPath}")
    }
}
