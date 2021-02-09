#define _ 1
#if __USER_LABEL_PREFIX__ + 0
#define label(N) _##N
#else
#define label(N) N
#endif

.global label(uc2_supermaster_compressed)
.global label(uc2_supermaster_compressed_end)

.data
label(uc2_supermaster_compressed):
.incbin "super.bin"
label(uc2_supermaster_compressed_end):
