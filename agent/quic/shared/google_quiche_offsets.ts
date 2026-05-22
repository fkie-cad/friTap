// agent/quic/shared/google_quiche_offsets.ts
//
// Struct offset tables for Google QUICHE (Chrome/Chromium/Cronet).
// These offsets are architecture and version-dependent.
//
// QuicSpdyStream inherits from QuicStream, which has:
//   - vtable pointer (offset 0, size pointerSize)
//   - QuicStream::id_ (QuicStreamId = uint32_t)
//   - QuicStream::session_ (QuicSession*)
//
// The exact offsets vary by Chrome version. The tables below are
// starting points derived from Chromium source analysis and need
// to be validated against specific builds.

export interface GoogleQuicheOffsets {
    /** Offset of QuicStream::id_ from QuicSpdyStream* this */
    streamId: number;
    /** Offset of QuicStream::session_ from QuicSpdyStream* this */
    session: number;
    /** Offset of QuicSession::connection_ from QuicSession* */
    connection: number;
    /** Offset of QuicConnection::direct_peer_address_ from QuicConnection* */
    peerAddress: number;
    /** Offset of QuicConnection::default_path_.self_address from QuicConnection* */
    selfAddress: number;
}

// Mangled C++ symbol names for QuicSpdyStream methods.
//
// IMPORTANT — string_view mangling: Chromium builds its own libc++ under the
// ABI namespace `std::__Cr` and aliases `absl::string_view` to
// `std::__Cr::basic_string_view<char, ...>` (ABSL_USES_STD_STRING_VIEW). So
// any method taking an absl::string_view mangles as
// `NSt4__Cr17basic_string_viewIcNS<n>_11char_traitsIcEEEE`, NOT
// `N4absl11string_viewE`. Verified on libmainlinecronet.141.0.7340.3.so via its
// MiniDebugInfo (.gnu_debugdata) symtab — the binary contains ZERO
// `absl::string_view` symbols. The old absl-based names below never resolved,
// which is why WriteOrBufferBody was silently never hooked.
export const MANGLED_SYMBOLS = {
    // QuicSpdyStream::Readv(const struct iovec*, size_t)
    readv: {
        linux: "_ZN4quic14QuicSpdyStream5ReadvEPK5iovecm",
        macos: "__ZN4quic14QuicSpdyStream5ReadvEPK5iovecm",
        // Windows uses MSVC mangling
        windows: "?Readv@QuicSpdyStream@quic@@MEAA_KPEBUiovec@@_K@Z",
    },
    // QuicSpdyStream::WriteOrBufferBody(std::__Cr::basic_string_view<char,...>, bool)
    // Outgoing HTTP/3 body (clean, de-framed). Verified mangled name.
    writeOrBufferBody: {
        linux: "_ZN4quic14QuicSpdyStream17WriteOrBufferBodyENSt4__Cr17basic_string_viewIcNS1_11char_traitsIcEEEEb",
        macos: "__ZN4quic14QuicSpdyStream17WriteOrBufferBodyENSt4__Cr17basic_string_viewIcNS1_11char_traitsIcEEEEb",
        windows: "?WriteOrBufferBody@QuicSpdyStream@quic@@MEAAXV?$basic_string_view@DU?$char_traits@D@__1@std@@@absl@@_N@Z",
    },
    // QuicSpdyStream::HttpDecoderVisitor::OnDataFramePayload(std::__Cr::basic_string_view<char,...>)
    // INCOMING HTTP/3 body — the HttpDecoder visitor callback. This is the clean
    // de-framed body Chrome actually delivers (its OnDataAvailable() drains the
    // sequencer via GetReadableRegion()+MarkConsumed() and runs HttpDecoder, so
    // QuicStreamSequencer::Readv is never on the body path and QuicSpdyStream::Readv
    // is inlined). NOTE: nested in QuicSpdyStream::HttpDecoderVisitor, so `this`
    // (args[0]) is the visitor sub-object, not the stream. Verified mangled name.
    onDataFramePayload: {
        linux: "_ZN4quic14QuicSpdyStream18HttpDecoderVisitor18OnDataFramePayloadENSt4__Cr17basic_string_viewIcNS2_11char_traitsIcEEEE",
        macos: "__ZN4quic14QuicSpdyStream18HttpDecoderVisitor18OnDataFramePayloadENSt4__Cr17basic_string_viewIcNS2_11char_traitsIcEEEE",
        windows: "?OnDataFramePayload@HttpDecoderVisitor@QuicSpdyStream@quic@@UEAA_NV?$basic_string_view@DU?$char_traits@D@__1@std@@@absl@@@Z",
    },
    // QuicStream::WriteOrBufferData(std::__Cr::basic_string_view<char,...>, bool,
    //   quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>)
    // Outgoing stream-level write (HTTP/3-framed bytes). Fallback for egress when
    // WriteOrBufferBody is unavailable. Verified mangled name.
    quicStreamWriteOrBufferData: {
        linux: "_ZN4quic10QuicStream17WriteOrBufferDataENSt4__Cr17basic_string_viewIcNS1_11char_traitsIcEEEEbN6quiche29QuicheReferenceCountedPointerINS_24QuicAckListenerInterfaceEEE",
        macos: "__ZN4quic10QuicStream17WriteOrBufferDataENSt4__Cr17basic_string_viewIcNS1_11char_traitsIcEEEEbN6quiche29QuicheReferenceCountedPointerINS_24QuicAckListenerInterfaceEEE",
        windows: "",
    },
    // QuicStreamSequencer::OnStreamFrame(const QuicStreamFrame&)
    // Broad raw-cleartext fallback (includes HTTP/3 framing). Arg is a struct
    // reference, not a string_view — extracting bytes needs QuicStreamFrame field
    // offsets, so this is resolved-only / opt-in, not attached by default.
    // Verified mangled name.
    sequencerOnStreamFrame: {
        linux: "_ZN4quic19QuicStreamSequencer13OnStreamFrameERKNS_15QuicStreamFrameE",
        macos: "__ZN4quic19QuicStreamSequencer13OnStreamFrameERKNS_15QuicStreamFrameE",
        windows: "?OnStreamFrame@QuicStreamSequencer@quic@@QEAAXAEBVQuicStreamFrame@2@@Z",
    },
    // QuicStream::Readv — base-class virtual. Survives when Chrome
    // devirtualises QuicSpdyStream::Readv on a release ARM64 build.
    quicStreamReadv: {
        linux: "_ZN4quic10QuicStream5ReadvEPK5iovecm",
        macos: "__ZN4quic10QuicStream5ReadvEPK5iovecm",
        windows: "?Readv@QuicStream@quic@@QEAA_KPEBUiovec@@_K@Z",
    },
    // QuicStreamSequencer::Readv — low-level read on the post-decrypt cleartext
    // ring buffer. Not virtual, not inlinable across the call boundary, so it's
    // the most reliable extraction point on Cronet's HTTP/3 body path.
    sequencerReadv: {
        linux: "_ZN4quic19QuicStreamSequencer5ReadvEPK5iovecm",
        macos: "__ZN4quic19QuicStreamSequencer5ReadvEPK5iovecm",
        windows: "?Readv@QuicStreamSequencer@quic@@QEAA_KPEBUiovec@@_K@Z",
    },
    // QuicSpdyStream::OnBodyAvailable — diagnostic only; fires when body bytes
    // arrive. Lets us prove the HTTP/3 stream reached the body stage even when
    // none of the Readv variants get called.
    onBodyAvailable: {
        linux: "_ZN4quic14QuicSpdyStream15OnBodyAvailableEv",
        macos: "__ZN4quic14QuicSpdyStream15OnBodyAvailableEv",
        windows: "?OnBodyAvailable@QuicSpdyStream@quic@@UEAAXXZ",
    },
    // QuicSpdyStream::OnHeadersDecoded(QuicHeaderList headers /*BY VALUE*/,
    //   bool header_list_size_limit_exceeded)
    // RELIABLE incoming/response decoded-headers path for the app-API capture
    // mode. NOTE the corrected signature: there is NO QuicStreamId argument.
    // ARM64: x0 = this (QuicSpdyStream*), x1 = pointer to the by-value
    // QuicHeaderList temp, w2 = bool. QuicHeaderList is in namespace quic, so it
    // mangles as a substitution `NS_14QuicHeaderListE`. The trailing `b` is the
    // bool. Verify length prefixes against a real libmonochrome/Cronet symtab.
    onHeadersDecoded: {
        linux: "_ZN4quic14QuicSpdyStream16OnHeadersDecodedENS_14QuicHeaderListEb",
        macos: "__ZN4quic14QuicSpdyStream16OnHeadersDecodedENS_14QuicHeaderListEb",
        windows: "?OnHeadersDecoded@QuicSpdyStream@quic@@UEAAXVQuicHeaderList@2@_N@Z",
    },
    // QuicSpdyStream::WriteHeaders(quiche::HttpHeaderBlock header_block /*BY VALUE*/,
    //   bool fin, quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>)
    // OUTGOING/request decoded-headers path for the app-API capture mode (the
    // egress twin of OnHeadersDecoded). ARM64: x0 = this (QuicSpdyStream*),
    // x1 = pointer to the by-value HttpHeaderBlock temp (non-trivial -> passed by
    // invisible reference), w2 = fin. Older QUICHE used spdy::SpdyHeaderBlock /
    // spdy::Http2HeaderBlock instead of quiche::HttpHeaderBlock — add those
    // variants if a target build predates the rename. VERIFY the mangling
    // (length prefixes + substitutions) against a real libmonochrome symtab;
    // on stripped builds this resolves via pattern/offset, not the symbol.
    writeHeaders: {
        linux: "_ZN4quic14QuicSpdyStream12WriteHeadersEN6quiche15HttpHeaderBlockEbNS1_29QuicheReferenceCountedPointerINS_24QuicAckListenerInterfaceEEE",
        macos: "__ZN4quic14QuicSpdyStream12WriteHeadersEN6quiche15HttpHeaderBlockEbNS1_29QuicheReferenceCountedPointerINS_24QuicAckListenerInterfaceEEE",
        windows: "",
    },
};

// Single source of truth linking friTap pattern/offset *labels* (used in
// default_patterns.json and the offsets file) to MANGLED_SYMBOLS *keys* (used by
// resolveQuicheSymbols). Covers all 8 keys; the two diagnostics
// (quicStreamWriteOrBufferData, onBodyAvailable) are included so they remain
// pattern/offset-resolvable even though they normally have empty pattern lists.
export const LABEL_TO_KEY: Record<string, keyof typeof MANGLED_SYMBOLS> = {
    QuicSpdyStream_Readv:              "readv",
    QuicStream_Readv:                  "quicStreamReadv",
    QuicStreamSequencer_Readv:         "sequencerReadv",
    QuicSpdyStream_OnDataFramePayload: "onDataFramePayload",
    QuicSpdyStream_WriteOrBufferBody:  "writeOrBufferBody",
    QuicStream_WriteOrBufferData:      "quicStreamWriteOrBufferData",
    QuicStreamSequencer_OnStreamFrame: "sequencerOnStreamFrame",
    QuicSpdyStream_OnBodyAvailable:    "onBodyAvailable",
    QuicSpdyStream_OnHeadersDecoded:   "onHeadersDecoded",
    QuicSpdyStream_WriteHeaders:        "writeHeaders",
};

export const KEY_TO_LABEL: Record<keyof typeof MANGLED_SYMBOLS, string> =
    Object.fromEntries(Object.entries(LABEL_TO_KEY).map(([label, key]) => [key, label])) as
        Record<keyof typeof MANGLED_SYMBOLS, string>;

// String literals that can be used to locate functions via xref scanning
export const STRING_MARKERS = {
    writeOrBufferBody: "writing body data",  // AssertNotWebTransportDataStream
};
