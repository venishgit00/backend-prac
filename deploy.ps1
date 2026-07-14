param([string]$message = "update")

git add .
git commit -m $message
git push
