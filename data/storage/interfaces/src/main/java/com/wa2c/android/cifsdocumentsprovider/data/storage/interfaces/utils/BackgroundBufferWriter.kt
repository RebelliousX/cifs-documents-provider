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
import kotlinx.coroutines.*
import java.io.Closeable
import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import kotlin.coroutines.CoroutineContext

class BackgroundBufferWriter(
    private val bufferSize: Int = DEFAULT_BUFFER_SIZE,
    private val queueCapacity: Int = DEFAULT_CAPACITY,
    override val coroutineContext: CoroutineContext = Dispatchers.IO + Job(),
    private val writeBackground: suspend CoroutineScope.(start: Long, array: ByteArray, off: Int, len: Int) -> Unit
) : CoroutineScope, Closeable {

    private val dataBufferQueue = ArrayBlockingQueue<WriteDataBuffer>(queueCapacity)
    private var currentBuffer: WriteDataBuffer? = null
    @Volatile private var closed = false

    init {
        launch(coroutineContext) {
            logD("[CYCLE] Writer started")
            while (isActive || dataBufferQueue.isNotEmpty()) {
                val buffer = dataBufferQueue.poll() ?: continue
                if (buffer.isEndOfData) break
                try {
                    writeBackground(buffer.position, buffer.data.array(), 0, buffer.length)
                } catch (e: Exception) {
                    logE(e)
                }
            }
            logD("[CYCLE] Writer ended")
        }
    }

    fun writeBuffer(writePosition: Long, writeSize: Int, writeData: ByteArray): Int {
        if (closed) return -1

        // Flush old buffer if discontinuous
        currentBuffer?.let {
            if (it.endPosition != writePosition) {
                flushBuffer(it)
                currentBuffer = null
            }
        }

        if (writeSize >= bufferSize) {
            // Direct enqueue for large writes
            flushBuffer(WriteDataBuffer(writePosition, ByteBuffer.wrap(writeData.copyOf(writeSize))))
            return writeSize
        }

        val buffer = currentBuffer ?: WriteDataBuffer(writePosition, ByteBuffer.allocate(bufferSize))
            .also { currentBuffer = it }

        if (buffer.data.remaining() < writeSize) {
            flushBuffer(buffer)
            currentBuffer = WriteDataBuffer(writePosition, ByteBuffer.allocate(bufferSize))
                .also { it.data.put(writeData, 0, writeSize) }
        } else {
            buffer.data.put(writeData, 0, writeSize)
        }

        return writeSize
    }

    private fun flushBuffer(buffer: WriteDataBuffer) {
        // Non-blocking flush: if full, retry
        while (!dataBufferQueue.offer(buffer)) {
            Thread.sleep(1) // Yield to background writer
        }
    }

    override fun close() {
        closed = true
        currentBuffer?.let { flushBuffer(it) }
        dataBufferQueue.offer(WriteDataBuffer.endOfData)
    }

    data class WriteDataBuffer(
        val position: Long,
        val data: ByteBuffer,
    ) {
        val length: Int get() = data.position()
        val endPosition: Long get() = position + length
        val isEndOfData: Boolean get() = position < 0

        companion object {
            val endOfData = WriteDataBuffer(-1, ByteBuffer.allocate(0))
        }
    }

    companion object {
        private const val DEFAULT_BUFFER_SIZE = 1024 * 1024 // 1MB
        private const val DEFAULT_CAPACITY = 32 // Bigger queue to prevent stall
    }
}
