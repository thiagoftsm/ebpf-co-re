#!/bin/bash

set -e

echo 1
./src/tests/core_tester --iteration 1 --buffer --log-path out_buffer_c.log 2> err_buffer_c.log
echo 2
./src/tests/core_tester_go --iteration 1 --buffer --log-path out_buffer_go.log 2> err_buffer_go.log

echo 3
./src/tests/core_tester --iteration 1 --arena --log-path out_arena_c.log 2> err_arena_c.log
echo 4
./src/tests/core_tester_go --iteration 1 --arena --log-path out_arena_go.log 2> err_arena_go.log
