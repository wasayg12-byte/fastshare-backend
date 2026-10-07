const crypto = require('crypto');

const MAX_MESSAGE_LENGTH = 4000;

function createMessage({ senderPhone, receiverPhone, textContent = '', fileUrl }) {
	const text = typeof textContent === 'string' ? textContent.trim() : '';
	const attachmentUrl = typeof fileUrl === 'string' ? fileUrl.trim() : '';

	if (!senderPhone || !receiverPhone) {
		throw new Error('A sender and receiver are required.');
	}
	if (text.length > MAX_MESSAGE_LENGTH) {
		throw new Error(`Messages must be ${MAX_MESSAGE_LENGTH} characters or fewer.`);
	}
	if (!text && !attachmentUrl) {
		throw new Error('Write a message or attach a file.');
	}

	return {
		id: crypto.randomUUID(),
		senderPhone,
		receiverPhone,
		textContent: text,
		timestamp: new Date().toISOString(),
		...(attachmentUrl ? { fileUrl: attachmentUrl } : {}),
	};
}

function isConversationMessage(message, user1, user2) {
	return (message.senderPhone === user1 && message.receiverPhone === user2)
		|| (message.senderPhone === user2 && message.receiverPhone === user1);
}

module.exports = { createMessage, isConversationMessage, MAX_MESSAGE_LENGTH };
