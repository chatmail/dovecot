AC_DEFUN([DOVECOT_WANT_CASSANDRA], [
  if test $want_cassandra != no; then
          AC_CHECK_LIB(cassandra, cass_session_new, [
                  AC_CHECK_HEADER(cassandra.h, [
                          CASSANDRA_LIBS="$CASSANDRA_LIBS -lcassandra"
  
                          AC_DEFINE(HAVE_CASSANDRA,, [Build with Cassandra support])
                          found_sql_drivers="$found_sql_drivers cassandra"
                          AC_CHECK_LIB(cassandra, cass_cluster_set_constant_speculative_execution_policy, [
                                       AC_DEFINE(HAVE_CASSANDRA_SPECULATIVE_POLICY, 1, [Cassandra supports speculative execution policy])
                          ])
                  ], [
                    if test $want_cassandra = yes; then
                      AC_ERROR([Can't build with Cassandra support: cassandra.h not found])
                    fi
                  ])
          ], [
            if test $want_cassandra = yes; then
              AC_ERROR([Can't build with Cassandra support: libcassandra not found])
            fi
          ])
  fi
])
