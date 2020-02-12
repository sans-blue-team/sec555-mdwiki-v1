#!/bin/bash

# Uncomment PDF settings
sed -in 's/#    - pdf-export/    - pdf-export/g' mkdocs.yml
sed -in 's/#          verbose/          verbose/g' mkdocs.yml
sed -in 's/#          media_type/          media_type/g' mkdocs.yml
sed -in 's/#          combined:/          combined:/g' mkdocs.yml
sed -in 's/#          enabled_if/          enabled_if/g' mkdocs.yml
sed -in 's/#  - css\/pdf/  - css\/pdf/g' mkdocs.yml

# Run mkdocs build
ENABLE_PDF_EXPORT=1 mkdocs build

# Move PDFs to pdf directory
find . -name *.pdf -exec /bin/cp -rf {} pdf \;

# Remove unnecessary PDFs
for i in $(ls -d pdf/* | grep -v sec555); do 
    rm "$i"
done
#rm pdf/Lab\ Template.pdf

# Comment PDF settings
sed -in 's/    - pdf-export/#    - pdf-export/g' mkdocs.yml
sed -in 's/          verbose/#          verbose/g' mkdocs.yml
sed -in 's/          media_type/#          media_type/g' mkdocs.yml
sed -in 's/          combined:/#          combined:/g' mkdocs.yml
sed -in 's/          enabled_if/#          enabled_if/g' mkdocs.yml
sed -in 's/  - css\/pdf/#  - css\/pdf/g' mkdocs.yml

# Beep to inform completion
printf "\a\a\a"
