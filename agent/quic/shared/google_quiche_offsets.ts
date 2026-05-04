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

// Mangled C++ symbol names for QuicSpdyStream methods
export const MANGLED_SYMBOLS = {
    // QuicSpdyStream::Readv(const struct iovec*, size_t)
    readv: {
        linux: "_ZN4quic14QuicSpdyStream5ReadvEPK5iovecm",
        macos: "__ZN4quic14QuicSpdyStream5ReadvEPK5iovecm",
        // Windows uses MSVC mangling
        windows: "?Readv@QuicSpdyStream@quic@@MEAA_KPEBUiovec@@_K@Z",
    },
    // QuicSpdyStream::WriteOrBufferBody(absl::string_view, bool)
    writeOrBufferBody: {
        linux: "_ZN4quic14QuicSpdyStream17WriteOrBufferBodyEN4absl11string_viewEb",
        macos: "__ZN4quic14QuicSpdyStream17WriteOrBufferBodyEN4absl11string_viewEb",
        windows: "?WriteOrBufferBody@QuicSpdyStream@quic@@MEAAXV?$basic_string_view@DU?$char_traits@D@__1@std@@@absl@@_N@Z",
    },
};

// String literals that can be used to locate functions via xref scanning
export const STRING_MARKERS = {
    writeOrBufferBody: "writing body data",  // AssertNotWebTransportDataStream
};
