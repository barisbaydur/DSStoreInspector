# DSStoreInspector
DSStoreInspector is a CLI tool for analyzing automatically created .DS_Store files on macOS systems and examining their contents in detail. These files usually contain directory view settings, but in some cases may also contain directory and file information.

When the tool starts, it will start downloading all directories and files referenced in the ds_store file (if the download feature is enabled). In some cases ds_store files can be detected in nested directories. In this case, if the recursive parameter is set, it will also download the files in that directory.

# Example Usage
```
DSStoreInspector.exe -url https://staticmedia.awms.apps.northwesternmutual.com/.DS_Store -download -recursive
```

# Help
```
Usage: DsStoreInspector.exe -url https://www.example.com/.DS_Store [options] <url>
  -download
        Download files to the current directory
  -recursive
        Recursively scan for .DS_Store files
  -threads int
        Number of threads to use for scanning (default 10)
  -url string
        The URL to start scanning from.
        Example: https://www.example.com/.DS_Store
```
