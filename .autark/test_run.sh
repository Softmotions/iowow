#!/bin/sh
# Runs a test executable given by the arguments.
#
# The test executables are started by Autark with stdout/stderr redirected into pipes,
# so the test harness cannot detect a terminal by itself. Colors are enabled when this
# script is started from a terminal (its stdin is inherited from Autark), unless they
# are disabled by NO_COLOR/IW_TEST_NO_COLOR or by the zero valued
# FORCE_COLOR/IW_TEST_COLOR/CLICOLOR_FORCE.
if [ -t 0 ]                                  \
   && [ -z "$NO_COLOR$IW_TEST_NO_COLOR" ]    \
   && [ "$IW_TEST_COLOR" != 0 ]              \
   && [ "$FORCE_COLOR" != 0 ]                \
   && [ "$CLICOLOR_FORCE" != 0 ]; then
  exec "$@" --color
fi
exec "$@"
