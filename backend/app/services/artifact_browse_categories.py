"""Stable, inexpensive file categories shared by browse listing and tree."""

# Categorization from recorded filenames only; never infer file contents.
FILE_CATEGORY_SQL = """CASE
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('pdf','doc','docx','odt','rtf','txt','ppt','pptx','xls','xlsx','csv') THEN 'Documents'
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('jpg','jpeg','png','gif','bmp','webp','heic','tif','tiff') THEN 'Images'
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('mp4','mov','avi','mkv','wmv','3gp','webm') THEN 'Videos'
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('mp3','wav','aac','m4a','ogg','flac') THEN 'Audio'
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('eml','emlx','msg','pst','ost','mbox') THEN 'Emails'
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('db','sqlite','sqlite3','db3','edb') THEN 'Databases'
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('zip','7z','rar','tar','gz','cab') THEN 'Archives'
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('lnk','url','history','evtx','log') THEN 'System artifacts'
 WHEN lower(ltrim(coalesce(extension,''), '.')) IN ('exe','dll','sys','apk','msi') THEN 'Executables'
 ELSE 'Other files' END"""

KNOWN_FILE_CATEGORIES = frozenset({
    'Documents', 'Images', 'Videos', 'Audio', 'Emails', 'Databases',
    'Archives', 'System artifacts', 'Executables', 'Other files',
})
