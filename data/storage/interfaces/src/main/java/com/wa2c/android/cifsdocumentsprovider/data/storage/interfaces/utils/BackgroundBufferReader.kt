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
import java.util.*
import kotlin.coroutines.CoroutineContext
import kotlin.math.min

/**
 * Efficient buffered reader for large data streams with background pre-fetching.
 *
 * Features:
 * - On-demand reading with LRU caching
 * - Background pre-fetching of adjacent buffers
 * - Thread-safe operations
 * - Optimized for both sequential and random access patterns
 *
 * @param streamSize Total size of the data stream in bytes
 * @param bufferSize Size of individual data buffers (default: 512KB)
 * @param cacheCapacity Maximum number of buffers to keep in memory (default: 50)
 * @param coroutineContext Execution context for background operations
 * @param readBackgroundAsync Asynchronous data reader function
 */
class BackgroundBufferReader(
    private val streamSize: Long,
    private val bufferSize: Int = DEFAULT_BUFFER_SIZE,
    private val cacheCapacity: Int = DEFAULT_CAPACITY,
    override val coroutineContext: CoroutineContext = Dispatchers.IO + Job(),
    private val readBackgroundAsync: CoroutineScope.(start: Long, array: ByteArray, off: Int, len: Int) -> Int
) : Closeable, CoroutineScope {

    /**
     * LRU cache for data buffers. Maintains most recently used buffers and evicts
     * least recently used buffers when capacity is exceeded.
     */
    private val cache = object : LinkedHashMap<Long, DataBuffer>(cacheCapacity, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, DataBuffer>?): Boolean {
            return size > cacheCapacity
        }
    }

    /** Synchronization lock for thread-safe cache access */
    private val cacheLock = Any()

    /**
     * Reads data from the stream into the provided buffer.
     *
     * @param readPosition Starting position in the stream (bytes)
     * @param readSize Number of bytes to read
     * @param readData Destination buffer for read data
     * @return Actual number of bytes read (0 if end of stream)
     */
    fun readBuffer(readPosition: Long, readSize: Int, readData: ByteArray): Int {
        // Validate input parameters
        if (readData.isEmpty()) return 0

        // Calculate maximum readable bytes (considering stream boundaries)
        val maxSize = min(readSize, readData.size).let {
            if (readPosition + it > streamSize) (streamSize - readPosition).toInt() else it
        }
        if (maxSize <= 0) return 0

        var readOffset = 0
        var currentPosition = readPosition

        // Read data in segments that may span multiple buffers
        while (readOffset < maxSize) {
            // Calculate start position of current buffer block
            val bufferStart = currentPosition / bufferSize * bufferSize

            // Retrieve or load buffer containing current position
            val buffer = getBuffer(bufferStart)

            // Calculate offset within current buffer
            val bufferOffset = (currentPosition - bufferStart).toInt()

            // Determine bytes available in current buffer
            val bytesToCopy = min(buffer.length - bufferOffset, maxSize - readOffset)

            // Copy data from buffer to output
            buffer.data.copyInto(
                destination = readData,
                destinationOffset = readOffset,
                startIndex = bufferOffset,
                endIndex = bufferOffset + bytesToCopy
            )

            // Update read state
            readOffset += bytesToCopy
            currentPosition += bytesToCopy

            // Pre-fetch adjacent buffers for potential future access
            prefetchAdjacentBuffers(bufferStart)
        }
        return readOffset
    }

    /**
     * Retrieves buffer from cache or loads it asynchronously.
     *
     * @param bufferStart Start position of the requested buffer
     * @return DataBuffer containing requested data
     */
    private fun getBuffer(bufferStart: Long): DataBuffer {
        return synchronized(cacheLock) {
            cache[bufferStart] ?: runBlocking {
                // Cache miss - load buffer synchronously
                readBufferAsync(bufferStart).also {
                    // Add to cache after loading
                    cache[bufferStart] = it
                }
            }
        }
    }

    /**
     * Asynchronously reads a buffer from the data source.
     *
     * @param bufferStart Start position of buffer to read
     * @return Loaded DataBuffer instance
     */
    private suspend fun readBufferAsync(bufferStart: Long): DataBuffer {
        // Calculate valid read size (considering stream end)
        val readSize = min(bufferSize.toLong(), streamSize - bufferStart).toInt()
        if (readSize <= 0) return DataBuffer(bufferStart, 0, ByteArray(0))

        val data = ByteArray(readSize)
        // Read primary data segment
        val size = readBackgroundAsync(bufferStart, data, 0, readSize)
        val remain = readSize - size

        // Handle partial reads by reading remaining data
        return if (size > 0 && remain > 0) {
            val subSize = readBackgroundAsync(bufferStart + size, data, size, remain)
            DataBuffer(bufferStart, size + subSize, data)
        } else {
            DataBuffer(bufferStart, size, data)
        }
    }

    /**
     * Pre-fetches adjacent buffers in the background to optimize sequential access.
     *
     * @param bufferStart Reference position for determining adjacent buffers
     */
    private fun prefetchAdjacentBuffers(bufferStart: Long) {
        launch {
            // Determine previous and next buffer positions
            listOf(bufferStart - bufferSize, bufferStart + bufferSize).forEach { position ->
                // Validate position is within stream bounds
                if (position >= 0 && position < streamSize) {
                    synchronized(cacheLock) {
                        // Only pre-fetch if not already in cache
                        if (!cache.containsKey(position)) {
                            cache[position] = runBlocking { readBufferAsync(position) }
                        }
                    }
                }
            }
        }
    }

    /** Releases all resources and cancels background operations */
    override fun close() {
        coroutineContext.cancel()
        synchronized(cacheLock) { cache.clear() }
    }

    /**
     * Represents a data buffer in memory.
     *
     * @property streamPosition Start position in the stream (bytes)
     * @property length Valid data length in the buffer (bytes)
     * @property data Raw byte array containing the data
     */
    data class DataBuffer(
        val streamPosition: Long,
        val length: Int,
        val data: ByteArray
    ) {
        /** Data end position (exclusive) */
        val endPosition: Long get() = streamPosition + length

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as DataBuffer
            return streamPosition == other.streamPosition &&
                    length == other.length &&
                    data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = streamPosition.hashCode()
            result = 31 * result + length
            result = 31 * result + data.contentHashCode()
            return result
        }
    }

    companion object {
        /** Default buffer size (512KB) */
        private const val DEFAULT_BUFFER_SIZE = BUFFER_SIZE

        /** Default cache capacity (30 buffers) */
        private const val DEFAULT_CAPACITY = 30
    }
}