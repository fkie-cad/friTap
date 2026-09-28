"""Unit tests for the TL schema parser and the vendored-schema registry."""

from __future__ import annotations

import pytest

from friTap.offline.mtproto.tl import load_schema, name_for_id, parse_tl
from friTap.offline.mtproto.tl.schema import parse_line, parse_type, tl_crc32

SAMPLE = """
int ? = Int;
long ? = Long;
string ? = String;
bytes = Bytes;
int128 4*[ int ] = Int128;
vector#1cb5c415 {t:Type} # [ t ] = Vector t;

// a whole-line comment
boolFalse#bc799737 = Bool;
user#b1b8cc83 flags:# self:flags.10?true flags2:# close_friend:flags2.2?true id:long first_name:flags.1?string = User;  // trailing
future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt;
future_salts#ae500895 req_msg_id:long now:int salts:vector<future_salt> = FutureSalts;
msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;
message msg_id:long seqno:int bytes:int body:Object = Message;
msg_container#73f1f8dc messages:vector<%Message> = MessageContainer;

---functions---

invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
help.getConfig#c4f9186b = Config;

---types---

pong#347773c5 msg_id:long ping_id:long = Pong;
"""


@pytest.fixture(scope="module")
def schema():
    return parse_tl(SAMPLE)


def test_builtin_definitions_are_skipped(schema):
    names = {c.name for c in schema.constructors.values()}
    assert not names & {"int", "long", "string", "bytes", "int128", "vector"}


def test_sections_split_constructors_and_functions(schema):
    assert schema.functions[0xDA9B0D0D].name == "invokeWithLayer"
    assert schema.functions[0xC4F9186B].is_function
    # ---types--- switches back: pong is a constructor again.
    assert 0x347773C5 in schema.constructors
    assert not schema.constructors[0x347773C5].is_function


def test_flag_params(schema):
    user = schema.constructors[0xB1B8CC83]
    by_name = {p.name: p for p in user.params}
    assert by_name["flags"].type == "#" and by_name["flags"].flag_field is None
    assert (by_name["self"].flag_field, by_name["self"].flag_bit, by_name["self"].type) == ("flags", 10, "true")
    assert (by_name["close_friend"].flag_field, by_name["close_friend"].flag_bit) == ("flags2", 2)
    assert (by_name["first_name"].type, by_name["first_name"].flag_bit) == ("string", 1)
    assert user.result_type == "User"


def test_generics_and_function_arg(schema):
    invoke = schema.functions[0xDA9B0D0D]
    assert invoke.generics == ("X",)
    assert [(p.name, p.type) for p in invoke.params] == [("layer", "int"), ("query", "!X")]
    assert invoke.result_type == "X"


def test_bare_combinator_gets_crc32_id(schema):
    message = schema.by_name["message"]
    assert message.id == 0x5BB8E511
    assert [p.name for p in message.params] == ["msg_id", "seqno", "bytes", "body"]


def test_by_type_index(schema):
    assert [c.name for c in schema.by_type["FutureSalt"]] == ["future_salt"]


def test_first_definition_wins():
    schema = parse_tl("a#00000001 x:int = A;\nb#00000001 y:long = B;")
    assert schema.constructors[1].name == "a"


@pytest.mark.parametrize(
    "line, expected",
    [
        ("boolFalse = Bool", 0xBC799737),
        ("message msg_id:long seqno:int bytes:int body:Object = Message", 0x5BB8E511),
        # flags.N?true params and bytes->string normalisation:
        ("account.registerDevice token_type:int token:string = Bool", 0x637EA878),
        ("ipPortSecret#37982646 ipv4:int port:int secret:bytes = IpPort", tl_crc32("ipPortSecret ipv4:int port:int secret:string = IpPort")),
        ("msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck", 0x62D6B459),
        ("invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X", 0xDA9B0D0D),
    ],
)
def test_tl_crc32(line, expected):
    assert tl_crc32(line) == expected


def test_unsupported_line_is_skipped():
    assert parse_line("garbage without equals") is None
    assert parse_line("weird#00000002 [ int ] = W;") is None


@pytest.mark.parametrize(
    "text, kind, name, elem",
    [
        ("int", "prim", "int", None),
        ("#", "prim", "#", None),
        ("true", "prim", "true", None),
        ("Bool", "bool", "Bool", None),
        ("!X", "function", "X", None),
        ("%Message", "bare", "Message", None),
        ("future_salt", "bare", "future_salt", None),
        ("User", "boxed", "User", None),
        ("messages.Dialogs", "boxed", "messages.Dialogs", None),
        ("Object", "boxed", "Object", None),
        ("Vector<long>", "vector", "Vector", "long"),
        ("vector<%Message>", "bare_vector", "vector", "Message"),
    ],
)
def test_parse_type(text, kind, name, elem):
    parsed = parse_type(text)
    assert (parsed.kind, parsed.name) == (kind, name)
    assert (parsed.elem.name if parsed.elem else None) == elem


def test_vendored_mtproto_domain_precedence():
    schema = load_schema("mtproto")
    assert name_for_id(0x62D6B459) == "msgs_ack"            # mtproto_api.tl
    assert name_for_id(0xF35C6D01) == "rpc_result"          # mtproto_core.tl
    assert name_for_id(0xDADBC950) == "account.getPrivacy"  # telegram_api.tl
    assert name_for_id(0x50A04E45) == "account.privacyRules"
    assert name_for_id(0x25939651) == "updates.getDifference"  # aliases.tl
    assert schema.constructors[0xB1B8CC83].name == "user"
    assert name_for_id(0xDEADBEEF) is None


def test_vendored_secret_domain():
    assert name_for_id(0x6719E45C, domain="secret") == "decryptedMessageActionFlushHistory"
    # telegram_api.tl sits below secret_api.tl in the secret stack.
    assert name_for_id(0xB1B8CC83, domain="secret") == "user"


def test_unknown_domain_rejected():
    with pytest.raises(ValueError):
        load_schema("nope")
