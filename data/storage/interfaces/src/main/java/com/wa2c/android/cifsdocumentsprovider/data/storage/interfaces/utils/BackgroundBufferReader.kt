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

import com.wa2c.android.cifsdocumentsprovider.common.values.BUFFER_SIZE
import kotlinx.coroutines.*
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.CoroutineContext
import kotlin.math.min

/**
 * Random-access safe SMB background buffer reader.
 * Always returns correct sequential bytes for any offset/length.
 */
class BackgroundBufferReader(
    private val streamSize: Long,
    private val bufferSize: Int = DEFAULT_BUFFER_SIZE,
    private val maxCacheBlocks: Int = DEFAULT_CACHE_BLOCKS,
    override val coroutineContext: CoroutineContext = Dispatchers.IO + SupervisorJob(),
    private val readBackgroundAsync: suspend (start: Long, array: ByteArray, off: Int, len: Int) -> Int
) : Closeable, CoroutineScope {

    /** LRU cache of blocks */
    private val cache = object : LinkedHashMap<Long, DataBuffer>(maxCacheBlocks, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, DataBuffer>?): Boolean {
            return size > maxCacheBlocks
        }
    }

    /** Pending block fetches to avoid duplicate reads */
    private val pendingFetches = ConcurrentHashMap<Long, Deferred<DataBuffer>>()

    private val cacheLock = Any()

    /**
     * Read exact data into readData. Will suspend until all requested bytes are ready or EOF.
     */
    suspend fun readBuffer(readPosition: Long, readSize: Int, readData: ByteArray): Int {
        if (readSize <= 0 || readData.isEmpty()) return 0

        val maxSize = min(readSize, readData.size).let {
            if (readPosition + it > streamSize) (streamSize - readPosition).toInt() else it
        }
        if (maxSize <= 0) return 0

        var totalRead = 0
        var currentPosition = readPosition

        while (totalRead < maxSize) {
            val blockStart = (currentPosition / bufferSize) * bufferSize
            val blockOffset = (currentPosition - blockStart).toInt()

            val block = getOrFetchBlock(blockStart)

            val toCopy = min(block.length - blockOffset, maxSize - totalRead)
            if (toCopy <= 0) break // EOF
            block.data.copyInto(readData, totalRead, blockOffset, blockOffset + toCopy)

            totalRead += toCopy
            currentPosition += toCopy
        }

        // Optional: prefetch next block to reduce lag
        prefetchAround(currentPosition)

        return totalRead
    }

    /**
     * Get a block, fetch if missing.
     */
    private suspend fun getOrFetchBlock(blockStart: Long): DataBuffer {
        synchronized(cacheLock) {
            cache[blockStart]?.let { return it }
        }

        val job = pendingFetches.computeIfAbsent(blockStart) {
            async {
                val size = min(bufferSize.toLong(), streamSize - blockStart).toInt()
                val data = ByteArray(size)
                var readBytes = readBackgroundAsync(blockStart, data, 0, size)
                if (readBytes in 1 until size) {
                    readBytes += readBackgroundAsync(blockStart + readBytes, data, readBytes, size - readBytes)
                }
                val block = DataBuffer(blockStart, readBytes, data)
                synchronized(cacheLock) { cache[blockStart] = block }
                pendingFetches.remove(blockStart)
                block
            }
        }

        return job.await()
    }

    /**
     * Prefetch next few blocks (async)
     */
    private fun prefetchAround(position: Long, count: Int = 2) {
        val startBlock = (position / bufferSize) * bufferSize
        for (i in 0 until count) {
            val blockStart = startBlock + i * bufferSize
            if (blockStart >= streamSize) break
            synchronized(cacheLock) {
                if (cache.containsKey(blockStart)) continue
            }
            if (!pendingFetches.containsKey(blockStart)) {
                launch { getOrFetchBlock(blockStart) }
            }
        }
    }

    override fun close() {
        cancel()
        synchronized(cacheLock) { cache.clear() }
        pendingFetches.clear()
    }

    data class DataBuffer(
        val streamPosition: Long,
        val length: Int,
        val data: ByteArray
    )

    companion object {
        // 1MB / buffer
        private const val DEFAULT_BUFFER_SIZE = BUFFER_SIZE
        // 32 buffers x 1MB = 32MB total
        private const val DEFAULT_CACHE_BLOCKS = 32
    }
}
