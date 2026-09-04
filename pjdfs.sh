#!/usr/bin/env bash

set -ex

exit_handler() {
    exit "$PJDFS_EXIT_STATUS"
}
trap exit_handler TERM
trap "kill 0" INT EXIT

export RUST_BACKTRACE=1

DATA_DIR=$(mktemp --directory)
DIR=$(mktemp --directory)

fuser -vvv --auto-unmount --suid --data-dir $DATA_DIR --mount-point $DIR $FUSER_URING_FLAGS > /code/logs/mount.log 2>&1 &
FUSE_PID=$!
sleep 0.5

echo "mounting at $DIR"
# Make sure FUSE was successfully mounted
mount | grep fuser

# A ring run that silently fell back to /dev/fuse must not pass as a ring run. Requests block
# until the queues are registered, so the line is there once stat returns; the timeout fails
# the run if a registered ring never serves
if [ -n "$FUSER_URING_FLAGS" ]; then
    timeout 30 stat "$DIR" > /dev/null
    grep 'io_uring: ring [0-9]* registered' /code/logs/mount.log
fi

set +e
cd ${DIR}
prove -rf /code/pjdfstest/tests | tee /code/logs/pjdfs.log
export PJDFS_EXIT_STATUS=${PIPESTATUS[0]}
echo "Total failed:"
cat /code/logs/pjdfs.log | egrep -o 'Failed: [0-9]+' | egrep -o '[0-9]+' | paste -s -d+ | bc

rm -rf ${DATA_DIR}

kill $FUSE_PID
wait $FUSE_PID
