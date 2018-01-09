#!/bin/sh -e

#Insert host specific valgrind supressions. Environment variables are
#provided by Jenkins. These are very verbose and most of the
#suppressions could be made more generic to suppress several instances
#of the same error. I keep them specific on purpose, to see new entry
#points to the buggy libraries.

NODE_NAME=${NODE_NAME:-"$1"}
WORKSPACE=${WORKSPACE:-"$2"}

case "$NODE_NAME" in
    *centos6-i386* | *centos-i386)
        echo "Adding some suppressions for $NODE_NAME unit tests."
        cat << EOF >> "$WORKSPACE"/run-test-valgrind.supp
{
   <centos6-i386-liblzma-uninitialized>
   Memcheck:Cond
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   obj:/usr/lib/liblzma.so.0.0.0
   fun:lzma_easy_encoder
   fun:o_stream_create_lzma
}
{
   <centos6-i386-openssl-compression-methods>
   Memcheck:Leak
   fun:malloc
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   fun:module_dir_init
   fun:dcrypt_initialize
   fun:main
}
EOF
   ;;
    *centos6.* | *centos6)
        echo "Adding some suppressions for $NODE_NAME unit tests."
        cat << EOF >> "$WORKSPACE"/run-test-valgrind.supp
{
   <centos6-liblzma-uninitialized>
   Memcheck:Cond
   obj:/usr/lib64/liblzma.so.0.0.0
   obj:/usr/lib64/liblzma.so.0.0.0
   obj:/usr/lib64/liblzma.so.0.0.0
   obj:/usr/lib64/liblzma.so.0.0.0
   fun:lzma_easy_encoder
   fun:o_stream_create_lzma
}
{
   <centos6-openssl-compression-methods>
   Memcheck:Leak
   fun:malloc
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   fun:module_dir_init
   fun:dcrypt_initialize
   fun:main
}
EOF
   ;;
    *squeeze*)
        echo "Adding some suppressions for $NODE_NAME unit tests."
        cat << EOF >> "$WORKSPACE"/run-test-valgrind.supp
{
   <squeeze-zlib-uninitialized>
   Memcheck:Cond
   fun:inflateReset2
   fun:inflateInit2_
   fun:i_stream_zlib_init
   fun:i_stream_create_zlib
   fun:test_compression_handler
   fun:test_compression
   fun:test_run_funcs
   fun:test_run
   fun:main
}
EOF
   ;;
    *wheezy*)
        echo "Adding some suppressions for $NODE_NAME unit tests."
        cat << EOF >> "$WORKSPACE"/run-test-valgrind.supp
{
   <squeeze-openssl-compression-methods>
   Memcheck:Leak
   fun:malloc
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   obj:*
   fun:module_dir_init
   fun:dcrypt_initialize
   fun:main
}
{
   <wheezy-openssl>
   Memcheck:Leak
   fun:malloc
   obj:*
   obj:*
   obj:*
   obj:*
   fun:(below main)
}
EOF
   ;;
    *jessie*)
        echo "Adding some suppressions for $NODE_NAME unit tests."
        cat << EOF >> "$WORKSPACE"/run-test-valgrind.supp
{
   <jessie-gethostbyname>
   Memcheck:Leak
   match-leak-kinds: definite
   fun:malloc
   fun:__res_vinit
   fun:__res_maybe_init
   fun:__nss_hostname_digits_dots
   fun:gethostbyname
   fun:my_hostdomain
}
EOF
   ;;
    *ubuntu1204* | *ubuntu1204)
        echo "Adding some suppressions for $NODE_NAME unit tests."
        cat << EOF >> "$WORKSPACE"/run-test-valgrind.supp
{
   <ubuntu-zlib-uninitialized>
   Memcheck:Cond
   fun:inflateReset2
   fun:inflateInit2_
   fun:i_stream_zlib_init
   fun:i_stream_create_gz
   fun:test_compression
   fun:test_run
   fun:main
}
{
   <ubuntu-zlib-uninitialized2>
   Memcheck:Cond
   fun:inflateReset2
   fun:inflateInit2_
   fun:i_stream_zlib_init
   fun:i_stream_create_deflate
   fun:test_compression
   fun:test_run
   fun:main
}
{
   <ubuntu-zlib-uninitialized3>
   Memcheck:Cond
   fun:inflateReset2
   fun:inflateInit2_
   fun:i_stream_create_gz
   fun:test_compression
   fun:test_run
   fun:main
}
{
   <ubuntu-zlib-uninitialized4>
   Memcheck:Cond
   fun:inflateReset2
   fun:inflateInit2_
   fun:i_stream_create_deflate
   fun:test_compression
   fun:test_run
   fun:main
}
{
   <ubuntu1204-zlib-uninitialized5>
   Memcheck:Cond
   fun:inflateReset2
   fun:inflateInit2_
   fun:i_stream_zlib_init
   fun:i_stream_create_zlib
   fun:test_compression_handler
   fun:test_compression
   fun:test_run_funcs
   fun:test_run
   fun:main
}
{
  <ubuntu1204-i386-zlib-uninitialized>
   Memcheck:Cond
   fun:inflateReset2
   fun:inflateInit2_
   fun:i_stream_zlib_init
   fun:i_stream_create_zlib
   fun:test_compression_handler
   obj:*
}
EOF
   ;;
    *)
        echo "No unit test suppressions for $NODE_NAME."
esac
