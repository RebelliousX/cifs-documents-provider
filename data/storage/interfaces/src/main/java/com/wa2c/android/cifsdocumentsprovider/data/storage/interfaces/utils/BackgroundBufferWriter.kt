/*
 * MIT License
 *
 * Copyright (c) 2021 wa2c
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.wa2c.android.cifsdocumentsprovider.data.storage.interfaces.utils

import com.wa2c.android.cifsdocumentsprovider.common.utils.logD
import com.wa2c.android.cifsdocumentsprovider.common.utils.logE
import com.wa2c.android.cifsdocumentsprovider.common.values.BUFFER_SIZE
import kotlinx.coroutines.*
import java.io.Closeable
import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import kotlin.coroutines.CoroutineContext

/**
 * BackgroundBufferWriter - Optimized non-blocking writer
 */
class BackgroundBufferWriter(
    /** Buffer unit size */
    private val bufferSize: Int = DEFAULT_BUFFER_SIZE,
    /** Buffer queue capacity */
    private val queueCapacity: Int = DEFAULT_CAPACITY,
    /** Coroutine context */
    override val coroutineContext: CoroutineContext = Dispatchers.IO + Job(),
    /** Background writing callback */
    private val writeBackground: suspend CoroutineScope.(position: Long, array: ByteArray, off: Int, len: Int) -> Unit
) : CoroutineScope, Closeable {

    /** Queue for pending writes */
    private val dataBufferQueue = ArrayBlockingQueue<WriteDataBuffer>(queueCapacity)

    /** Current write buffer */
    private var currentBuffer: WriteDataBuffer? = null

    /** Async background writer */
    private val writingJob = launch(coroutineContext) {
        logD("[WRITE-CYCLE] Begin: bufferSize=$bufferSize")
        while (isActive) {
            try {
                val dataBuffer = dataBufferQueue.take()
                if (dataBuffer.isEndOfData) break

                // Only write if it has actual data
                if (dataBuffer.length > 0) {
                    logD("[WRITE-CYCLE] Writing: position=${dataBuffer.position}, length=${dataBuffer.length}")
                    writeBackground(dataBuffer.position, dataBuffer.data.array(), 0, dataBuffer.length)
                }
            } catch (e: Exception) {
                logE(e)
            }
        }
        logD("[WRITE-CYCLE] End")
    }

    /**
     * Write buffer (non-blocking)
     */
    fun writeBuffer(writePosition: Long, writeSize: Int, writeData: ByteArray): Int {
        var remaining = writeSize
        var offset = 0

        while (remaining > 0) {
            var buffer = currentBuffer

            if (buffer == null || buffer.isFull || buffer.endPosition != writePosition + offset) {
                // flush current buffer if exists
                buffer?.let { enqueueBuffer(it) }

                // create new buffer aligned at this position
                buffer = WriteDataBuffer(writePosition + offset, ByteBuffer.allocate(bufferSize))
                currentBuffer = buffer
            }

            val toCopy = minOf(remaining, buffer.data.remaining())
            buffer.data.put(writeData, offset, toCopy)

            offset += toCopy
            remaining -= toCopy

            if (buffer.isFull) {
                enqueueBuffer(buffer)
                currentBuffer = null
            }
        }

        return writeSize
    }

    /**
     * Enqueue a buffer for background writing
     */
    private fun enqueueBuffer(buffer: WriteDataBuffer) {
        buffer.data.flip() // prepare for reading
        dataBufferQueue.put(buffer)
    }

    /**
     * Close the writer and flush everything
     */
    override fun close() {
        logD("close() called, flushing buffers")
        runBlocking(coroutineContext) {
            currentBuffer?.let {
                enqueueBuffer(it)
                currentBuffer = null
            }
            // enqueue end signal
            dataBufferQueue.put(WriteDataBuffer.endOfData)
            writingJob.join()
            logD("Writing job finished")
        }
    }

    /**
     * Data buffer class
     */
    data class WriteDataBuffer(
        /** Start position in stream */
        val position: Long,
        /** Byte buffer */
        val data: ByteBuffer
    ) {
        val length: Int
            get() = data.position()
        val endPosition: Long
            get() = position + length
        val isFull: Boolean
            get() = !data.hasRemaining()
        val isEndOfData: Boolean
            get() = position < 0

        companion object {
            /** End flag data */
            val endOfData = WriteDataBuffer(-1, ByteBuffer.allocate(0))
        }
    }

    companion object {
        // 1MB / buffer
        private const val DEFAULT_BUFFER_SIZE = BUFFER_SIZE
        // 32 buffers x 1MB = 32MB total
        private const val DEFAULT_CAPACITY = 32
    }
}
