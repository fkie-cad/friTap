// MTProto service combinators that TDLib's mtproto_api.tl keeps commented out
// (TDLib parses them natively). friTap's TL decoder needs them spelled out.
// Every line below is the commented-out line of mtproto_api.tl (see SOURCE.txt),
// with the `string` placeholders TDLib uses replaced by the real `Object` type
// (https://core.telegram.org/mtproto/service_messages).
// Precedence (mtproto domain): mtproto_api.tl > mtproto_core.tl > telegram_api.tl > aliases.tl

rpc_result#f35c6d01 req_msg_id:long result:Object = RpcResult;
destroy_session_ok#e22045fc session_id:long = DestroySessionRes;
destroy_session_none#62d350c9 session_id:long = DestroySessionRes;
msg_container#73f1f8dc messages:vector<%Message> = MessageContainer;
message msg_id:long seqno:int bytes:int body:Object = Message;
msg_copy#e06046b2 orig_message:Message = MessageCopy;

---functions---

ping#7abe77ec ping_id:long = Pong;
destroy_session#e7512126 session_id:long = DestroySessionRes;
