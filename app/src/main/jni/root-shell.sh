#!/system/bin/sh
dir=/data/local/tmp/dfroot-shell
umask 007

mkdir -p "$dir" || exit 1
: > "$dir/in" || exit 1
: > "$dir/out" || exit 1
chmod 0770 "$dir" || exit 1
chmod 0660 "$dir/in" "$dir/out" || exit 1
chown 0:2000 "$dir" "$dir/in" "$dir/out" || exit 1
id > "$dir/status"
chmod 0644 "$dir/status"
setprop debug.dfroot.ready 1

while true; do
    if [ ! -s "$dir/in" ]; then
        sleep 0.2
        continue
    fi
    IFS= read -r command < "$dir/in"
    : > "$dir/in"
    if [ "$command" = ':exit' ]; then
        echo 'root command channel stopped' > "$dir/out"
        break
    fi
    eval "$command" > "$dir/out" 2>&1
    printf '\n__DFROOT_DONE__:%d\n' "$?" >> "$dir/out"
done
