Upstream: datagram-socket 0.8.1, commit b364ea80f9b9cf204f0f0ce0507de2b132bac0f5.
Crates.io archive SHA-256: 532e26edbe1cbfcc6a94ecf2e339cc727cc245fc63ff1f831acd07e27d7a94e1.

Only src/mmsg.rs differs: two libc::msghdr literals become zero-initialized values with iovec pointer and length assignments; an unused import is removed. musl libc hides padding fields, so literals fail compilation. Null pointers, zero lengths and flags are valid msghdr values; subsequent assignments preserve upstream syscall behavior. Retire patch when an upstream release supports musl construction.
