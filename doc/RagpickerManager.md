#Ragpicker Manager (manager.py)

###Usage

```
./manager.py -h
usage: manager.py [-h] {stop,export,vxcage,import,sort} ...

Ragpicker Manager

optional arguments:
  -h, --help            show this help message and exit

subcommands:
  valid subcommands

  {stop,export,vxcage,import,sort}
                        additional help
    stop                Stops a running Ragpicker instance
    export              Export Ragpicker-Data
    vxcage              Exports only the malware files from the VxCage
    import              Import Ragpicker-Data
    sort                Sort malware files by file type
```

##Stop

Stops a running ragpicker instance.

##Export

Export Ragpicker data.

###Usage

```
manager.py export -h
usage: manager.py export [-h] -d DIRNAME -f SHA256_FILE [--json JSON]

optional arguments:
  -h, --help            show this help message and exit
  -d DIRNAME, --dirname DIRNAME
                        Export-Directory
  -f SHA256_FILE, --sha256_file SHA256_FILE
                        SHA256-File
  --json JSON           File in json-format? Default=False
```

##VxCage-Export

Exports only the malware files from the VxCage.

```
./manager.py vxcage -h
usage: manager.py vxcage [-h] -d DIRNAME -f SHA256_FILE [--json JSON]

optional arguments:
  -h, --help            show this help message and exit
  -d DIRNAME, --dirname DIRNAME
                        Export-Directory
  -f SHA256_FILE, --sha256_file SHA256_FILE
                        SHA256-File
  --json JSON           File in json-format? Default=False
```

##Sort

Sort malware files by file type e.g.

```
.../Downloads/malware_sort/
├── 7-zip
├── Composite
├── ELF
├── MS-DOS
├── PDF
├── PE32
├── PE32+
├── RAR
├── Rich
└── Zip
```

###Usage

```
./manager.py sort -h
usage: manager.py sort [-h] -s SOURCE_DIR -d DESTINATION_DIR

optional arguments:
  -h, --help            show this help message and exit
  -s SOURCE_DIR, --source_dir SOURCE_DIR
                        Source-Directory
  -d DESTINATION_DIR, --destination_dir DESTINATION_DIR
                        Destination-Directory
```

##SHA256-File format

###Format 1:

flat sha256 hash file e.g.

```
884bf70feb3ba9aeaad49700d2956b9d494be1e32fe8de779d4022f3db806d63
992bdc76042aa942579803ca8929d6cd1c8c2d6c067ac01ab9af0c9bd8c19996
3f7185437df941ef789bd79bc75328e712bb95bf1e960ecad1ff53084e7644f5
b3d7fb29b78909a139958a3864b66a000cc42f5a0ae0a9321503182560211f31
12be221f75eba9e25cabf0b0e82a78925790a5516d7a189748882fce8d2194b0
```

###Format 2:

sha256 file json-style (switch '--json true') e.g.

```
{
    "0" : "884bf70feb3ba9aeaad49700d2956b9d494be1e32fe8de779d4022f3db806d63",
    "1" : "992bdc76042aa942579803ca8929d6cd1c8c2d6c067ac01ab9af0c9bd8c19996",
    "2" : "3f7185437df941ef789bd79bc75328e712bb95bf1e960ecad1ff53084e7644f5",
    "3" : "b3d7fb29b78909a139958a3864b66a000cc42f5a0ae0a9321503182560211f31",
    "4" : "12be221f75eba9e25cabf0b0e82a78925790a5516d7a189748882fce8d2194b0",
    "5" : "f07a7f348e3c61e45d04ced0d92a818bfc1abc6ef7607365c8eea49221e103a3"
}
```

##Generating sha256 json file with ragpicker mongo database:

all files:

```
get_sha256 = function(doc) { return doc.Info.file.sha256; }
db.ragpicker.find().map( get_sha256 );
```

for example only driver files:

```
get_sha256 = function(doc) { return doc.Info.file.sha256; }
 db.ragpicker.find({"Info.file.DRIVER" : true, "Info.file.DLL" : false}, { "Info.file.sha256": 1, _id:0}).map( get_sha256 );
```