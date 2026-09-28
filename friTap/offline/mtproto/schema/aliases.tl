// Old-layer / pinned constructors, loaded at the LOWEST precedence: an id that
// the vendored telegram_api.tl / mtproto_api.tl / secret_api.tl also defines
// always resolves to the vendored definition. Entries here keep ids decodable
// that a Telegram client in the field still sends but a newer schema dropped
// (or may drop). Every entry carries a "// source:" line saying where its
// layout comes from and how it was verified.

// source: telegram_api.tl @ tdlib/td 42e6a5259551178d1dab54a22ad96d14bd906e20 (the current
// `user` constructor, copied verbatim). Verified 2026-09-25 against a real
// user#b1b8cc83 record of an Android Telegram capture (e2e.pcapng): every field
// consumed, first_name == "Evil". Pinned here so the capture stays decodable
// once a future schema bump renumbers `user`.
user#b1b8cc83 flags:# self:flags.10?true contact:flags.11?true mutual_contact:flags.12?true deleted:flags.13?true bot:flags.14?true bot_chat_history:flags.15?true bot_nochats:flags.16?true verified:flags.17?true restricted:flags.18?true min:flags.20?true bot_inline_geo:flags.21?true support:flags.23?true scam:flags.24?true apply_min_photo:flags.25?true fake:flags.26?true bot_attach_menu:flags.27?true premium:flags.28?true attach_menu_enabled:flags.29?true flags2:# bot_can_edit:flags2.1?true close_friend:flags2.2?true stories_hidden:flags2.3?true stories_unavailable:flags2.4?true contact_require_premium:flags2.10?true bot_business:flags2.11?true bot_has_main_app:flags2.13?true bot_forum_view:flags2.16?true bot_forum_can_manage_topics:flags2.17?true bot_can_manage_bots:flags2.18?true bot_guestchat:flags2.19?true bot_guard:flags2.20?true id:long access_hash:flags.0?long first_name:flags.1?string last_name:flags.2?string username:flags.3?string phone:flags.4?string photo:flags.5?UserProfilePhoto status:flags.6?UserStatus bot_info_version:flags.14?int restriction_reason:flags.18?Vector<RestrictionReason> bot_inline_placeholder:flags.19?string lang_code:flags.22?string emoji_status:flags.30?EmojiStatus usernames:flags2.0?Vector<Username> stories_max_id:flags2.5?RecentStory color:flags2.8?PeerColor profile_color:flags2.9?PeerColor bot_active_users:flags2.12?int bot_verification_icon:flags2.14?long send_paid_messages_stars:flags2.15?long linked_community_id:flags2.21?long = User;

---functions---

// source: pre-layer-1xx updates.getDifference, still sent by Telegram Android
// (DrKLO/Telegram TLRPC.java TL_updates_getDifference, constructor 0x25939651:
// flags, pts, pts_total_limit if flags.0, date, qts). Id reproduced by the TL
// CRC32 of this line; verified 2026-09-25 against a real client write in
// e2e.pcapng (24 B, all fields consumed).
updates.getDifference#25939651 flags:# pts:int pts_total_limit:flags.0?int date:int qts:int = updates.Difference;

// source: old-layer account.registerDevice (token_type:int token:string), still
// sent by Telegram Android for token_type 7 (MTProto push session). Id reproduced
// by the TL CRC32 of this line; verified 2026-09-25 against a real client write
// in e2e.pcapng (32 B, all fields consumed).
account.registerDevice#637ea878 token_type:int token:string = Bool;
