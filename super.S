#define concat_(A,B) A##B
#define concat(A,B) concat_(A,B)
#define symbol(N) concat(__USER_LABEL_PREFIX__,N)

.global symbol(uc2_supermaster_compressed)
.global symbol(uc2_supermaster_compressed_end)

.data
.align 1
symbol(uc2_supermaster_compressed):
.incbin "super.bin"
symbol(uc2_supermaster_compressed_end):
