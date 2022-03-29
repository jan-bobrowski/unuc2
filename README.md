
# unuc2

Library for unpacking UC2 archives.

Ultra Compressor II is a compression utility from DOS era
that achieved much better compression than ZIP by combining similiar files.
Original author was so kind to [publish source code](http://www.nicodevries.com/professional/)
that made the library possible.

## API

* uc2_identify – check UC2 magic
* uc2_open – initialize
* uc2_read_cdir – read dir entry
* uc2_get_tag – read tag
* uc2_finish_cdir – get archive label
* uc2_extract – decompress a file
* uc2_message – get error message
* uc2_close – free resources

See [libunuc2.h](libunuc2.h) for details.
