# The files that update a device to this version, cut from the built image:
#
#   viaos_<v>.efi                   the UKI
#   viaos_<v>_<uuid>.store.raw.zst  the erofs /nix/store partition
#   viaos_<v>_<uuid>.verity.raw.zst its verity hash partition
#   manifest.json                   version, arch, variant (if not the plain
#                                   OS) and each file's sha256
#
# The UUIDs are the ones repart derived from the verity root hash, which is
# how the UKI's usrhash finds its partitions. sysupdate writes them back onto
# the partitions it fills.
{
  runCommand,
  jq,
  zstd,
  util-linux,
  image,
  uki,
  version,
  arch,
  # VARIANT_ID, e.g. `nvidia`; null for the plain OS. A device installs only
  # its own variant.
  variant ? null,
}:
runCommand "viaos-update-${version}"
  {
    nativeBuildInputs = [
      jq
      zstd
      util-linux
    ];
  }
  ''
    mkdir -p $out
    raw=${image}/viaos_${version}.raw
    meta=${image}/repart-output.json

    # Offsets and sizes come from the partition table; the UUIDs from repart.
    extract() {
      local label=$1 suffix=$2
      local uuid start size
      uuid=$(jq -r --arg l "$label" '.[] | select(.label == $l) | .uuid' $meta)
      start=$(sfdisk -J $raw | jq -r --arg l "$label" '.partitiontable.partitions[] | select(.name == $l) | .start')
      size=$(sfdisk -J $raw | jq -r --arg l "$label" '.partitiontable.partitions[] | select(.name == $l) | .size')
      dd if=$raw bs=512 skip=$start count=$size status=none \
        | zstd -T0 -q -o $out/viaos_${version}_$uuid.$suffix.raw.zst
    }
    extract viaos_${version} store
    extract viaos_${version}_v verity
    cp ${uki} $out/viaos_${version}.efi

    (cd $out && for f in viaos_*; do
      jq -n --arg n "$f" --arg h "$(sha256sum $f | cut -d' ' -f1)" --argjson s "$(stat -c %s $f)" \
        '{name: $n, sha256: $h, size: $s}'
    done) | jq -s --arg v ${version} --arg a ${arch} --arg var "${toString variant}" \
      '{version: $v, arch: $a} + (if $var == "" then {} else {variant: $var} end) + {files: .}' \
      > $out/manifest.json
  ''
