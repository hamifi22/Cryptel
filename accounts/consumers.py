import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)

class CallConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        self.room_name = f'call_{self.user.id}'
        logger.info(f"WebSocket connected for user {self.user.id}, room: {self.room_name}")
        try:
            await self.channel_layer.group_add(self.room_name, self.channel_name)
            await self.accept()
        except Exception as e:
            logger.error(f"Error in connect: {e}")
            raise

    async def disconnect(self, close_code):
        logger.info(f"WebSocket disconnected for user {self.user.id}, code: {close_code}")
        await self.channel_layer.group_discard(self.room_name, self.channel_name)

    async def receive(self, text_data):
        logger.info(f"Received WebSocket message: {text_data}")
        try:
            data = json.loads(text_data)
            message_type = data['type']
            receiver_id = data.get('receiver_id')

            if message_type == 'call_initiate':
                await self.channel_layer.group_send(
                    f'call_{receiver_id}',
                    {
                        'type': 'call_initiate_message',
                        'caller_id': self.user.id,
                        'caller_name': self.user.username
                    }
                )
            elif message_type == 'offer':
                await self.channel_layer.group_send(
                    f'call_{receiver_id}',
                    {
                        'type': 'offer_message',
                        'offer': data['offer'],
                        'caller_id': self.user.id
                    }
                )
            elif message_type == 'accept':
                await self.channel_layer.group_send(
                    f'call_{receiver_id}',
                    {
                        'type': 'accept_message',
                        'receiver_id': receiver_id
                    }
                )
            elif message_type == 'reject':
                await self.channel_layer.group_send(
                    f'call_{receiver_id}',
                    {'type': 'reject_message', 'receiver_id': receiver_id}
                )
            elif message_type == 'answer':
                await self.channel_layer.group_send(
                    f'call_{receiver_id}',
                    {'type': 'answer_message', 'answer': data['answer'], 'caller_id': self.user.id}
                )
            elif message_type == 'ice_candidate':
                await self.channel_layer.group_send(
                    f'call_{receiver_id}',
                    {'type': 'ice_candidate_message', 'candidate': data['candidate'], 'caller_id': self.user.id}
                )
        except Exception as e:
            logger.error(f"Error in receive: {e}")

    async def call_initiate_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'call_initiate',
            'caller_id': event['caller_id'],
            'caller_name': event['caller_name']
        }))

    async def offer_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'offer',
            'offer': event['offer'],
            'caller_id': event['caller_id']
        }))

    async def accept_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'accept',
            'receiver_id': event['receiver_id']
        }))

    async def reject_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'reject',
            'receiver_id': event['receiver_id']
        }))

    async def answer_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'answer',
            'answer': event['answer'],
            'caller_id': event['caller_id']
        }))

    async def ice_candidate_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'ice_candidate',
            'candidate': event['candidate'],
            'caller_id': event['caller_id']
        }))