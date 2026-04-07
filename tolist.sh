for f in ./comment/*.md; do
  name=$(basename "$f" .md)
  echo "- [$name]($f)"
done