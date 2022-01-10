package com.wa2c.android.cifsdocumentsprovider.domain.repository

import android.net.Uri
import com.wa2c.android.cifsdocumentsprovider.common.utils.logE
import com.wa2c.android.cifsdocumentsprovider.common.values.SendDataState
import com.wa2c.android.cifsdocumentsprovider.data.io.DataSender
import com.wa2c.android.cifsdocumentsprovider.domain.model.SendData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.IOException
import java.util.*
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SendRepository @Inject constructor(
    private val dataSender: DataSender
) {

    private val _sendFlow: MutableSharedFlow<SendData?> = MutableSharedFlow(0, 1, BufferOverflow.DROP_OLDEST)
    val sendFlow: Flow<SendData?> = _sendFlow

    /**
     * Get send data list.
     */
    suspend fun getSendData(sourceUris: List<Uri>, targetUri: Uri): List<SendData> {
        return withContext(Dispatchers.IO) {
            sourceUris.mapNotNull { uri ->
                dataSender.getDocumentFile(uri)?.let { file ->
                    SendData(
                        UUID.randomUUID().toString(),
                        file.name ?: file.uri.lastPathSegment ?: return@mapNotNull null,
                        file.length(),
                        file.type?.ifEmpty { null } ?: OTHER_MIME_TYPE,
                        file.uri,
                        targetUri,
                    ).also {
                        if (existsTarget(it)) {
                            it.state = SendDataState.OVERWRITE
                        }
                    }
                }
            }
        }
    }

    /**
     * True if target exists.
     */
    private fun existsTarget(sendData: SendData): Boolean {
        return dataSender.getDocumentFile(sendData.targetUri)?.let {
            if (it.isDirectory) {
                it.findFile(sendData.name)?.exists() == true
            } else {
                it.exists()
            }
        } ?: false
    }

    /**
     * Send a data.
     */
    suspend fun send(sendData: SendData): SendDataState {
        return withContext(Dispatchers.IO) {
            if (!sendData.state.isReady) return@withContext sendData.state
            sendData.state = SendDataState.PROGRESS

            var previousTime = 0L
            val targetFile = dataSender.getDocumentFile(sendData.targetUri)?.let {
                if (it.isDirectory) {
                    val file = it.findFile(sendData.name)
                    if (file?.exists() == true) {
                        file
                    } else {
                        it.createFile(sendData.mimeType, sendData.name)
                    }
                } else {
                    it
                }
            } ?: throw IOException()

            sendData.startTime = System.currentTimeMillis()
            val isSuccess = dataSender.sendFile(sendData.sourceUri, targetFile.uri) { progressSize ->
                if (!sendData.state.inProgress) {
                    return@sendFile false
                }
                if (!isActive) {
                    sendData.state = SendDataState.FAILURE
                    return@sendFile false
                }
                val currentTime = System.currentTimeMillis()
                if (currentTime >= previousTime + NOTIFY_CYCLE) {
                    sendData.progressSize = progressSize
                    _sendFlow.tryEmit(sendData)
                    previousTime = currentTime
                }
                return@sendFile true
            }

            if (isSuccess) {
                SendDataState.SUCCESS
            } else if (sendData.state == SendDataState.PROGRESS) {
                SendDataState.FAILURE
            }

            sendData.state = when {
                isSuccess -> SendDataState.SUCCESS
                sendData.state == SendDataState.PROGRESS -> SendDataState.FAILURE
                else -> sendData.state
            }

            // Delete if incomplete
            if (sendData.state.isIncomplete) {
                try {
                    targetFile.delete()
                } catch (e: Exception) {
                    logE(e)
                }
            }

            sendData.state
        }
    }

    companion object {
        private const val NOTIFY_CYCLE = 1000
        private const val OTHER_MIME_TYPE =  "application/octet-stream"
    }

}